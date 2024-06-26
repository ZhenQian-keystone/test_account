use crate::error::convert_mnemonic_to_key::ConvertMnemonicToKeyError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GenerateKeyError {
    #[error("Failed to convert mnemonic to key")]
    ConvertMnemonicToKeyFailed(#[source] ConvertMnemonicToKeyError),

    #[error("Failed to generate a fresh secp256k1 key")]
    GenerateFreshSecp256k1KeyFailed(#[source] Box<k256::elliptic_curve::Error>),
}
