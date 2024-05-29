use crate::error::convert_mnemonic_to_key::ConvertMnemonicToKeyError;
use crate::error::convert_mnemonic_to_key::ConvertMnemonicToKeyError::DeriveExtendedKeyFromPathFailed;
use crate::error::generate_key::GenerateKeyError;
use crate::error::generate_key::GenerateKeyError::GenerateFreshSecp256k1KeyFailed;

use bip32::XPrv;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use k256::pkcs8::LineEnding;
use k256::SecretKey;
use sec1::EncodeEcPrivateKey;
/// Generates a new secp256k1 key.
pub fn generate_key() -> Result<(Vec<u8>, Mnemonic), GenerateKeyError> {
    let mnemonic: Mnemonic =
        Mnemonic::new(MnemonicType::for_key_size(256).unwrap(), Language::English);
    let secret: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
        mnemonic_to_key(&mnemonic).map_err(GenerateKeyError::ConvertMnemonicToKeyFailed)?;
    let pem: sec1::der::zeroize::Zeroizing<String> = secret
        .to_sec1_pem(LineEnding::CRLF)
        .map_err(|e| GenerateFreshSecp256k1KeyFailed(Box::new(e)))?;
    Ok((pem.as_bytes().to_vec(), mnemonic))
}

pub fn mnemonic_to_key(mnemonic: &Mnemonic) -> Result<SecretKey, ConvertMnemonicToKeyError> {
    const DEFAULT_DERIVATION_PATH: &str = "m/44'/223'/0'/0/0";
    let path: bip32::DerivationPath = DEFAULT_DERIVATION_PATH.parse().unwrap();
    let seed: Seed = Seed::new(mnemonic, "");
    let pk: bip32::ExtendedPrivateKey<k256::ecdsa::SigningKey> =
        XPrv::derive_from_path(seed.as_bytes(), &path).map_err(DeriveExtendedKeyFromPathFailed)?;
    Ok(SecretKey::from(pk.private_key()))
}

#[cfg(test)]
mod tests {
    use bip32::PublicKey;

    use super::*;

    #[test]
    fn generate_key_words() {
        let (key, mnemonic) = generate_key().unwrap();
        println!("key: {:?}", key);
        println!("mnemonic: {:?}", mnemonic.phrase());
    }

    #[test]
    fn mnemonic_to_private_key() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(phrase, mnemonic.phrase());
        let priv_key: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
            mnemonic_to_key(&mnemonic).unwrap();
        let public_key: k256::elliptic_curve::PublicKey<k256::Secp256k1> = priv_key.public_key();
        println!("{:?}", public_key.to_bytes().len());
    }
}
