// SPDX-License-Identifier: MPL-2.0

//! Trusted Host consumers of the same exclusive whole-buffer protocol.
//! Local wrappers retain the allocation after endpoint close. No pool lock is
//! held while a caller reads or writes bytes, and no slice can escape a callback.

use core::ops::Range;

use super::*;

/// One Host-local participant, bound by the Host before publishing discovery.
pub struct HostLocalEndpoint {
    holder: Arc<Participant>,
    connection: u64,
}

/// A reserved receiver import credit, obtained before offering a transmit token.
pub struct HostSendCredit {
    sender: Arc<Participant>,
    peer: Arc<Participant>,
    connection: u64,
    reservation: Reservation,
}

/// Exclusive or read-only CPU access to independently owned shared storage.
/// This wrapper has no clone, mapping, frame, address, or backing-owner accessor.
pub struct HostLocalGrant {
    holder: Arc<Participant>,
    allocation: Arc<Allocation>,
    token: u64,
    writable: bool,
    payload: usize,
}

impl HostLocalEndpoint {
    /// Returns metadata admission for the participant, inbox, peer and two
    /// notifier entries. Payload allocations carry their own separate charge.
    pub const fn reservation_bytes() -> usize {
        // Include the larger private inboxes on both ends and their separate
        // quota metadata; packet records retain their own independent charge.
        4 * PAGE_SIZE
    }

    pub(crate) fn bind(account: Arc<Account>, image: &Arc<Participant>) -> Result<Self> {
        let holder = Participant::new_inner(account, true);
        let connection = Participant::connect(&holder, image)?;
        Ok(Self { holder, connection })
    }

    /// Returns this endpoint's Host-authorized nonreusable connection identity.
    pub fn connection(&self) -> u64 {
        self.connection
    }

    /// Installs bounded wake callbacks before publishing the connection. A
    /// successful handoff invokes its destination callback after unlocking POOL.
    /// Callbacks should retain only weak device/instance references.
    pub fn set_notifiers(
        &self,
        local_fn: Arc<dyn Fn() + Send + Sync>,
        image_fn: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<()> {
        let _pool = POOL.lock();
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let peer = self
            .holder
            .peers
            .lock()
            .get(&self.connection)
            .and_then(Peer::upgrade)
            .ok_or(Error::AccessDenied)?;
        if !peer.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        if self.holder.notifiers.lock().contains_key(&self.connection)
            || peer.notifiers.lock().contains_key(&self.connection)
        {
            return Err(Error::InvalidArgs);
        }
        self.holder
            .notifiers
            .lock()
            .insert(self.connection, local_fn);
        peer.notifiers.lock().insert(self.connection, image_fn);
        Ok(())
    }

    /// Allocates and activates initialized storage using a retained admission charge.
    pub fn allocate(
        &self,
        capacity: usize,
        admission: Box<dyn Send + Sync>,
    ) -> Result<HostLocalGrant> {
        let reply = execute(
            &self.holder,
            ALLOCATE,
            0,
            [capacity as u64, 0, 0],
            |_| Ok(admission),
            |_, _| unreachable!(),
        )?;
        self.redeem(reply.value)
    }

    fn redeem(&self, token: u64) -> Result<HostLocalGrant> {
        let mut pool = POOL.lock();
        self.redeem_locked(&mut pool, token)
    }

    /// Allocates one separately charged private NIC page without consuming
    /// the participant's ordinary shared-buffer allocation quota.
    pub fn allocate_net(&self, admission: Box<dyn Send + Sync>) -> Result<HostLocalGrant> {
        let reply = execute(
            &self.holder,
            SHARED_NET_ALLOCATE,
            0,
            [PAGE_SIZE as u64, self.connection, 0],
            |_| Ok(admission),
            |_, _| unreachable!(),
        )?;
        self.redeem(reply.value)
    }

    fn redeem_locked(
        &self,
        pool: &mut BTreeMap<u32, Record>,
        token: u64,
    ) -> Result<HostLocalGrant> {
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let record = owned(pool, &self.holder, token)?;
        if !matches!(record.state, State::Issued) {
            return Err(Error::InvalidArgs);
        }
        let grant = HostLocalGrant {
            holder: self.holder.clone(),
            allocation: record.allocation.clone(),
            token,
            writable: record.writable,
            payload: record.payload,
        };
        record.state = State::Active;
        self.holder
            .inbox
            .lock()
            .retain(|&(_, pending)| pending != token);
        Ok(grant)
    }

    /// Receives at most one owning delivery. No sender retains a local accessor.
    pub fn receive(&self) -> Result<Option<HostLocalGrant>> {
        let mut pool = POOL.lock();
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let token = self
            .holder
            .inbox
            .lock()
            .iter()
            .find_map(|&(connection, token)| (connection == self.connection).then_some(token));
        token
            .map(|token| self.redeem_locked(&mut pool, token))
            .transpose()
    }

    /// Activates a checked prefix of private-link deliveries under one pool lock.
    pub fn receive_batch(
        &self,
        received: &mut [Option<HostLocalGrant>; SHARED_NET_BATCH_SIZE],
    ) -> Result<usize> {
        if received.iter().any(Option::is_some) {
            return Err(Error::InvalidArgs);
        }
        let mut pool = POOL.lock();
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let mut inbox = self.holder.inbox.lock();
        let mut tokens = [0; SHARED_NET_BATCH_SIZE];
        let mut count = 0;
        for &(_, token) in inbox
            .iter()
            .filter(|&&(link, _)| link == self.connection)
            .take(SHARED_NET_BATCH_SIZE)
        {
            let record = owned(&mut pool, &self.holder, token)?;
            if !matches!(record.state, State::Issued) || record.connection != Some(self.connection)
            {
                return Err(Error::InvalidArgs);
            }
            tokens[count] = token;
            count += 1;
        }
        // Validate the complete prefix before changing any owner or inbox.
        for (slot, &token) in received.iter_mut().zip(&tokens[..count]) {
            let record = pool.get_mut(&(token as u32)).unwrap();
            *slot = Some(HostLocalGrant {
                holder: self.holder.clone(),
                allocation: record.allocation.clone(),
                token,
                writable: record.writable,
                payload: record.payload,
            });
            record.state = State::Active;
        }
        let mut remaining = count;
        inbox.retain(|&(link, _)| {
            if link == self.connection && remaining != 0 {
                remaining -= 1;
                false
            } else {
                true
            }
        });
        Ok(count)
    }

    /// Publishes one bounded private-link batch with a single peer notification.
    /// Every delivery carries its own previously admitted import credit.
    /// Rejection leaves all wrappers and credits in their original slots.
    pub fn handoff_batch(
        &self,
        deliveries: &mut [Option<(HostLocalGrant, HostSendCredit, usize)>; SHARED_NET_BATCH_SIZE],
    ) -> Result<usize> {
        if deliveries.iter().all(Option::is_none) {
            return Ok(0);
        }
        // The caller exclusively borrows all wrappers throughout this call.
        // Duplicate detection needs no mutable registry or peer state.
        for (index, delivery) in deliveries.iter().enumerate() {
            if let Some((grant, _, _)) = delivery
                && deliveries[..index]
                    .iter()
                    .flatten()
                    .any(|(other, _, _)| other.token == grant.token)
            {
                return Err(Error::InvalidArgs);
            }
        }
        let mut pool = POOL.lock();
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let peer = self
            .holder
            .peers
            .lock()
            .get(&self.connection)
            .and_then(Peer::upgrade)
            .ok_or(Error::AccessDenied)?;
        if !peer.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let mut next = [0; SHARED_NET_BATCH_SIZE];
        let mut count = 0;
        for (index, delivery) in deliveries.iter().enumerate() {
            let Some((grant, credit, payload)) = delivery else {
                continue;
            };
            if *payload > grant.capacity()
                || !grant.writable
                || !Arc::ptr_eq(&grant.holder, &self.holder)
                || !Arc::ptr_eq(&credit.sender, &self.holder)
                || !Arc::ptr_eq(&credit.peer, &peer)
                || credit.connection != self.connection
                || credit.reservation.bytes < grant.capacity()
            {
                return Err(Error::InvalidArgs);
            }
            let record = owned(&mut pool, &self.holder, grant.token)?;
            if !matches!(record.state, State::Active) || !record.writable {
                return Err(Error::InvalidArgs);
            }
            next[index] = advance(grant.token)?;
            count += 1;
        }
        let notify = peer.notifiers.lock().get(&self.connection).cloned();
        let mut inbox = peer.inbox.lock();
        for (index, slot) in deliveries.iter_mut().enumerate() {
            let Some((mut grant, credit, payload)) = slot.take() else {
                continue;
            };
            let record = pool.get_mut(&(grant.token as u32)).unwrap();
            inbox.push((self.connection, next[index]));
            record.publish(Delivery {
                holder: peer.clone(),
                token: next[index],
                connection: self.connection,
                access: GrantAccess::ReadWrite,
                payload,
                credit: credit.reservation,
                local_data_credit: None,
            });
            grant.token = 0;
        }
        drop(inbox);
        drop(pool);
        if let Some(notify) = notify {
            notify();
        }
        Ok(count)
    }

    /// Reserves bounded destination capacity before a producer fills storage.
    pub fn reserve_send(&self, capacity: usize) -> Result<HostSendCredit> {
        // A credit alone publishes no access. A close may race this bounded
        // reservation; handoff rechecks both participants under POOL.
        if !self.holder.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let peer = self
            .holder
            .peers
            .lock()
            .get(&self.connection)
            .and_then(Peer::upgrade)
            .ok_or(Error::AccessDenied)?;
        if !peer.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let reservation = Reservation::private_net(&peer.net_imports, capacity)?;
        Ok(HostSendCredit {
            sender: self.holder.clone(),
            peer,
            connection: self.connection,
            reservation,
        })
    }

    /// Observes destination capacity for worker polling. This does not reserve
    /// it; producers must still obtain their owning credit before writing.
    pub fn can_send(&self, capacity: usize) -> bool {
        if !self.holder.live.load(Ordering::Acquire) {
            return false;
        }
        self.holder
            .peers
            .lock()
            .get(&self.connection)
            .and_then(Peer::upgrade)
            .is_some_and(|peer| {
                peer.live.load(Ordering::Acquire)
                    && peer.net_imports.count.load(Ordering::Acquire) < PRIVATE_NET_IMPORTS
                    && peer
                        .net_imports
                        .bytes
                        .load(Ordering::Acquire)
                        .checked_add(capacity)
                        .is_some_and(|bytes| bytes <= MAX_BYTES)
            })
    }

    /// Stops future transitions; existing local byte borrows retain their storage.
    pub fn close(&self) {
        let image_notifier = {
            let _pool = POOL.lock();
            // Stop handoffs before retiring either callback. In-flight callback
            // clones may finish, but only retain their own bounded wake state.
            self.holder.mark_dying();
            self.holder
                .peers
                .lock()
                .get(&self.connection)
                .and_then(Peer::upgrade)
                .and_then(|peer| peer.notifiers.lock().remove(&self.connection))
        };
        self.holder.close();
        // A callback's captures may own arbitrary Host resources.
        drop(image_notifier);
    }
}

impl Drop for HostLocalEndpoint {
    fn drop(&mut self) {
        self.close();
    }
}

impl HostLocalGrant {
    /// Returns the initialized allocation size, including page rounding.
    pub fn capacity(&self) -> usize {
        self.allocation.dma.size()
    }

    /// Returns the useful byte count published by the preceding sender.
    pub fn payload_len(&self) -> usize {
        self.payload
    }

    /// Returns whether this local grant permits exclusive mutation.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Borrows a bounded byte range, with a result independent of its lifetime.
    pub fn with_bytes<R>(
        &self,
        range: Range<usize>,
        read_fn: impl for<'a> FnOnce(&'a [u8]) -> R,
    ) -> Result<R> {
        if range.start > range.end || range.end > self.payload {
            return Err(Error::InvalidArgs);
        }
        let address = self.allocation.dma.reader()?.cursor().addr();
        // SAFETY: An active owning grant excludes Image/backend access. The Arc
        // retains initialized storage even if teardown removes its pool record.
        // The higher-ranked callback prevents a reference from escaping.
        let bytes = unsafe {
            core::slice::from_raw_parts((address + range.start) as *const u8, range.len())
        };
        Ok(read_fn(bytes))
    }

    /// Exclusively borrows initialized capacity without exposing the backing owner.
    pub fn with_bytes_mut<R>(
        &mut self,
        range: Range<usize>,
        write_fn: impl for<'a> FnOnce(&'a mut [u8]) -> R,
    ) -> Result<R> {
        if !self.writable || range.start > range.end || range.end > self.capacity() {
            return Err(Error::InvalidArgs);
        }
        let address = self.allocation.dma.reader()?.cursor().addr();
        // SAFETY: The mutable wrapper borrow excludes every other local accessor;
        // whole-buffer ownership excludes Image/backend aliases. The callback
        // cannot return a reference, and its storage hold survives close.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut((address + range.start) as *mut u8, range.len())
        };
        Ok(write_fn(bytes))
    }

    /// Consumes local access using a previously reserved peer import slot.
    /// A rejected transition returns both owners unchanged.
    #[allow(clippy::result_large_err)]
    pub fn handoff(
        mut self,
        credit: HostSendCredit,
        payload: usize,
    ) -> core::result::Result<(), (Self, HostSendCredit, Error)> {
        let mut credit = Some(credit);
        let result = (|| {
            let reserved = credit.as_ref().unwrap();
            if payload > self.capacity()
                || !self.writable
                || !Arc::ptr_eq(&self.holder, &reserved.sender)
                || reserved.reservation.bytes < self.capacity()
            {
                return Err(Error::InvalidArgs);
            }
            let mut pool = POOL.lock();
            if !self.holder.live.load(Ordering::Acquire)
                || !reserved.peer.live.load(Ordering::Acquire)
            {
                return Err(Error::AccessDenied);
            }
            let record = owned(&mut pool, &self.holder, self.token)?;
            if !matches!(record.state, State::Active) || !record.writable {
                return Err(Error::InvalidArgs);
            }
            let next = advance(self.token)?;
            let credit = credit.take().unwrap();
            let notify = credit
                .peer
                .notifiers
                .lock()
                .get(&credit.connection)
                .cloned();
            credit.peer.inbox.lock().push((credit.connection, next));
            record.publish(Delivery {
                holder: credit.peer.clone(),
                token: next,
                connection: credit.connection,
                access: GrantAccess::ReadWrite,
                payload,
                credit: credit.reservation,
                local_data_credit: None,
            });
            Ok(notify)
        })();
        let notify = match result {
            Ok(notify) => notify,
            Err(error) => return Err((self, credit.unwrap(), error)),
        };
        self.token = 0;
        if let Some(notify) = notify {
            notify();
        }
        Ok(())
    }
}

impl Drop for HostLocalGrant {
    fn drop(&mut self) {
        if self.token == 0 {
            return;
        }
        let removed = {
            let mut pool = POOL.lock();
            if pool.get(&(self.token as u32)).is_some_and(|record| {
                record.token == self.token
                    && Arc::ptr_eq(&record.holder, &self.holder)
                    && matches!(record.state, State::Active)
            }) {
                pool.remove(&(self.token as u32))
            } else {
                None
            }
        };
        drop(removed);
    }
}
