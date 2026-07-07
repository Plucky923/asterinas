// SPDX-License-Identifier: MPL-2.0

//! Minimal device helpers used by copied syscall handlers.

use ostd::sync::{Once, SpinLock};
use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::prelude::*;

static RNG: Once<SpinLock<StdRng>> = Once::new();

/// Initializes device helpers used by copied syscall handlers.
pub fn init() -> Result<()> {
    let seed = get_random_seed()?;
    RNG.call_once(|| SpinLock::new(StdRng::from_seed(seed)));
    Ok(())
}

/// Fills a user writer with random bytes.
pub fn geturandom(writer: &mut VmWriter<'_>) -> Result<usize> {
    const IO_CAPABILITY: usize = 4096;

    if !writer.has_avail() {
        return Ok(0);
    }

    let mut buffer = vec![0; writer.avail().min(IO_CAPABILITY)];
    let mut written_bytes = 0;

    while writer.has_avail() {
        let write_len = writer.avail().min(IO_CAPABILITY);
        getrandom_bytes(&mut buffer[..write_len]);
        match writer.write_fallible(&mut VmReader::from(&buffer[..write_len])) {
            Ok(len) => written_bytes += len,
            Err((err, 0)) if written_bytes == 0 => return Err(err.into()),
            Err((_, len)) => return Ok(written_bytes + len),
        }
    }

    Ok(written_bytes)
}

/// Fills a user writer with random bytes.
pub use geturandom as getrandom;

/// Fills `dst` with random bytes from the `framev-rng` backed kernel RNG.
pub fn getrandom_bytes(dst: &mut [u8]) {
    RNG.get()
        .expect("kernel device RNG must be initialized before use")
        .lock()
        .fill_bytes(dst);
}

fn get_random_seed() -> Result<<StdRng as SeedableRng>::Seed> {
    let rng = framev_bus::rng().map_err(|err| Error::with_message(Errno::EINVAL, err.message()))?;
    let mut seed = <StdRng as SeedableRng>::Seed::default();
    framev_rng_frontend::fill_bytes(seed.as_mut())
        .map_err(|err| Error::with_message(Errno::EINVAL, err.message()))?;
    ostd::early_println!("use randomness provided by FrameV device {:?}", rng.id());
    Ok(seed)
}
