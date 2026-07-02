use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Length of the derived symmetric key, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the KDF salt, in bytes.
pub const SALT_LEN: usize = 16;

// Argon2id parameters. Tuned for at-rest file encryption on a modern laptop:
// ~64 MiB memory, 3 passes. Raise for higher-value secrets.
const M_COST_KIB: u32 = 65_536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

/// Derive a 32-byte key from a passphrase and salt using Argon2id.
///
/// The returned key zeroizes its memory on drop.
pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(KEY_LEN)).map_err(|_| Error::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|_| Error::Kdf)?;
    Ok(key)
}
