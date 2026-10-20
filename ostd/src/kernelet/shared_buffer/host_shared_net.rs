// SPDX-License-Identifier: MPL-2.0

//! Bounded private-NIC exchanges using one checked, pinned Image DMA scratch.

use super::*;
use crate::{kernelet::guest_memory::GuestMemory, mm::paddr_to_vaddr};

pub(crate) fn dispatch_net_exchange(
    holder: &Arc<Participant>,
    memory: &GuestMemory,
    token: u64,
    args: [u64; 3],
) -> MmioResult {
    let result = (|| {
        if token != 0 || args[2] > SHARED_NET_BATCH_SIZE as u64 {
            return Err(Error::InvalidArgs);
        }
        // Pin the entire input/output before any grant transition. Using the
        // registered DMA mapping also excludes typed Image objects and stacks.
        let _pin = memory.pin_registered_dma(args[1], NET_EXCHANGE_BYTES)?;
        let address = paddr_to_vaddr(args[1] as usize);
        // SAFETY: The pin retains this participant's registered, initialized
        // untyped DMA range. VM I/O copies metadata without forming references
        // to Image-owned bytes. No accessor escapes this synchronous service.
        let mut reader =
            unsafe { VmReader::from_kernel_space(address as *const u8, NET_RETURN_BYTES) };
        let mut returns = [0; SHARED_NET_BATCH_SIZE];
        for token in &mut returns[..args[2] as usize] {
            *token = reader.read_val()?;
        }
        // SAFETY: The same pin covers the whole descriptor output. Direct-map
        // VM writes cannot fault or lose the mapping after ownership changes.
        let mut writer = unsafe {
            VmWriter::from_kernel_space(
                (address + NET_RETURN_BYTES) as *mut u8,
                NET_EXCHANGE_BYTES - NET_RETURN_BYTES,
            )
        };
        exchange(holder, args[0], &returns[..args[2] as usize], &mut writer)
    })();
    result.unwrap_or_else(error_response)
}

fn exchange(
    holder: &Arc<Participant>,
    connection: u64,
    returns: &[u64],
    writer: &mut VmWriter<'_, Infallible>,
) -> Result<MmioResult> {
    if returns.len() > SHARED_NET_BATCH_SIZE
        || writer.avail() < NET_EXCHANGE_BYTES - NET_RETURN_BYTES
    {
        return Err(Error::InvalidArgs);
    }
    let mut pool = POOL.lock();
    if !holder.live.load(Ordering::Acquire) {
        return Err(Error::AccessDenied);
    }
    let peer = holder
        .peers
        .lock()
        .get(&connection)
        .filter(|peer| peer.host_local)
        .ok_or(Error::AccessDenied)?
        .upgrade();
    let peer_live = peer
        .as_ref()
        .is_some_and(|peer| peer.live.load(Ordering::Acquire));
    if !returns.is_empty() && !peer_live {
        return Err(Error::AccessDenied);
    }

    // Reserve every destination credit and nonwrapping generation before
    // accepting the first return. Duplicate tokens must not consume one grant
    // twice. Reservations roll back automatically if any precheck fails.
    let mut credits: [Option<Reservation>; SHARED_NET_BATCH_SIZE] = core::array::from_fn(|_| None);
    let mut next_tokens = [0; SHARED_NET_BATCH_SIZE];
    for (index, &token) in returns.iter().enumerate() {
        if returns[..index].contains(&token) {
            return Err(Error::InvalidArgs);
        }
        let record = owned(&mut pool, holder, token)?;
        if !matches!(record.state, State::Active) || !record.writable {
            return Err(Error::InvalidArgs);
        }
        next_tokens[index] = advance(token)?;
        credits[index] = Some(Reservation::new(
            &peer.as_ref().unwrap().imports,
            record.allocation.dma.size(),
        )?);
    }

    let mut inbox = holder.inbox.lock();
    let mut descriptors = [NetGrantDescriptor::default(); SHARED_NET_BATCH_SIZE];
    let mut received = 0;
    for &(_, token) in inbox
        .iter()
        .filter(|&&(pending, _)| pending == connection)
        .take(SHARED_NET_BATCH_SIZE)
    {
        let record = owned(&mut pool, holder, token)?;
        if !matches!(record.state, State::Issued) || record.connection != Some(connection) {
            return Err(Error::InvalidArgs);
        }
        descriptors[received] = NetGrantDescriptor {
            token,
            address: record.allocation.dma.reader()?.cursor().addr() as u64,
            mapping: mapping_info(
                record.allocation.dma.size(),
                record.payload,
                record.writable,
            ),
        };
        received += 1;
    }
    if received == 0 && !peer_live {
        return Err(Error::AccessDenied);
    }

    // All remaining operations are infallible. The output accessor already
    // retains the complete mapping; no allocation or fresh pin follows commit.
    for descriptor in &descriptors[..received] {
        pool.get_mut(&(descriptor.token as u32)).unwrap().state = State::Active;
    }
    let mut remaining = received;
    inbox.retain(|&(pending, _)| {
        if pending == connection && remaining != 0 {
            remaining -= 1;
            false
        } else {
            true
        }
    });
    let more_pending = inbox.iter().any(|&(pending, _)| pending == connection);
    drop(inbox);

    let mut notify = None;
    if !returns.is_empty() {
        let peer = peer.unwrap();
        notify = peer.notifiers.lock().get(&connection).cloned();
        let mut peer_inbox = peer.inbox.lock();
        for (index, &token) in returns.iter().enumerate() {
            let record = pool.get_mut(&(token as u32)).unwrap();
            peer_inbox.push((connection, next_tokens[index]));
            record.publish(Delivery {
                holder: peer.clone(),
                token: next_tokens[index],
                connection,
                access: GrantAccess::ReadWrite,
                payload: 0,
                credit: credits[index].take().unwrap(),
                local_data_credit: None,
            });
        }
    }
    // Copy only the populated prefix. Empty polling touches no output bytes;
    // packet payload storage never passes through this scratch.
    let bytes = ostd_pod::IntoBytes::as_bytes(&descriptors[..received]);
    let copied = writer.write(&mut VmReader::from(bytes));
    debug_assert_eq!(copied, bytes.len());
    drop(pool);
    if let Some(notify) = notify {
        notify();
    }
    Ok(response(i64::from(more_pending), received as u64))
}
