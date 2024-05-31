#![allow(unused_imports)]
use std::str::FromStr;

use crate::error::convert_mnemonic_to_key::ConvertMnemonicToKeyError;
use crate::error::convert_mnemonic_to_key::ConvertMnemonicToKeyError::DeriveExtendedKeyFromPathFailed;
use crate::error::generate_key::GenerateKeyError;
use crate::error::generate_key::GenerateKeyError::GenerateFreshSecp256k1KeyFailed;

use super::principal_id::PrincipalId;
use bip32::{PublicKeyBytes, XPrv};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PublicKey;
use k256::pkcs8::LineEnding;
use k256::Secp256k1;
use k256::{
    ecdsa::{self, signature::Signer, SigningKey},
    pkcs8::{Document, EncodePublicKey},
    SecretKey,
};
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

// pub fn public_key_to_principal_id(
//     public_key_vec: &[u8; 33],
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let public_key_bytes = PublicKeyBytes::from(*public_key_vec);
//     let public_key = PublicKey<Secp256k1>::fr
//     // // let public_key_der =
//     // let principal_id = PrincipalId::new_self_authenticating(&public_key_bytes);
//     // principal_id
//     Ok(())
// }

pub fn sign_message(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let signing_key: SigningKey = SigningKey::from(secret_key);
    let signature: Signature = signing_key.sign(message);
    signature
}

pub fn verify_signature(
    public_key: &PublicKey<Secp256k1>,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let secp = VerifyingKey::try_from(public_key).unwrap();
    secp.verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use bip32::{PrivateKey, PublicKey};
    use k256::elliptic_curve::{sec1::ToEncodedPoint, SecretKey};
    use sec1::der::Encode;

    use super::*;

    #[test]
    fn generate_key_words() {
        let (key, mnemonic) = generate_key().unwrap();
        println!("key: {:?}", key.len());
        println!("mnemonic: {:?}", mnemonic.phrase());
    }

    #[test]
    fn test_private_key_pem() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        let priv_key: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
            mnemonic_to_key(&mnemonic).unwrap();
        let pem: sec1::der::zeroize::Zeroizing<String> = priv_key
            .to_sec1_pem(LineEnding::CRLF)
            .map_err(|e| GenerateFreshSecp256k1KeyFailed(Box::new(e)))
            .unwrap();
        // sava pem to file
        let pem_str = pem.to_string();
        let mut file = std::fs::File::create("private.pem").unwrap();
        file.write(pem_str.as_bytes()).unwrap();
    }

    #[test]
    fn test_principal_id_from_private_key_str() {
        let priv_key_str =
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42".to_string();
        let priv_key_bytes = hex::decode(priv_key_str).unwrap();
        // let der_priv_key = priv_key_bytes.to_der().unwrap();
        let private_key = SecretKey::<Secp256k1>::from_slice(&priv_key_bytes).unwrap();
        let public_key = private_key.public_key();
        let der_public_key = public_key.to_public_key_der().unwrap();
        let principal_id: PrincipalId =
            PrincipalId::new_self_authenticating(&der_public_key.as_bytes());
        assert_eq!(
            "ogeza-v2sup-7el77-mls7v-kjxbs-tzekc-gywh3-dzikt-qisuu-xsc46-mqe",
            principal_id.to_string()
        );
    }

    #[test]
    fn test_sig_message_from_private_key_str() {
        let priv_key_str =
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42".to_string();
        let priv_key_bytes = hex::decode(priv_key_str).unwrap();
        let private_key = SecretKey::<Secp256k1>::from_slice(&priv_key_bytes).unwrap();
        let message = "0a69632d72657175657374957985b77f030ee246db6a464dc8c90bac5e50a40da8d5a2edf27ef6a7a91806";
        let message_vec = hex::decode(message).unwrap();
        assert_eq!(
            [
                10, 105, 99, 45, 114, 101, 113, 117, 101, 115, 116, 149, 121, 133, 183, 127, 3, 14,
                226, 70, 219, 106, 70, 77, 200, 201, 11, 172, 94, 80, 164, 13, 168, 213, 162, 237,
                242, 126, 246, 167, 169, 24, 6
            ],
            message_vec.as_slice()
        );
        let signature = sign_message(&private_key, &message_vec.as_slice());
        assert_eq!("5AC5681380CC61F253F736CE0B5844E064D50D09107DA142433350D0C5E47BF2296ECD2E2D8954C1E6A00A7314FF5E3A3024BA1C4E6AF6B7C12A1620E96195E8".to_string(), signature.to_string());
        let sig = "1afb8d355f2dc195079740d9077ea9e6b199111528aaa379ea50522b4e385dd719166331b5f62fc74e908da01c35be70a3eba4458817716da26107e0c8097de7";
        let py_sig = Signature::from_str(sig).unwrap();
        let verify_res = verify_signature(&private_key.public_key(), &message_vec, &py_sig);
        assert_eq!(true, verify_res);
    }

    #[test]
    fn mnemonic_to_private_key() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(phrase, mnemonic.phrase());
        let priv_key: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
            mnemonic_to_key(&mnemonic).unwrap();
        // let public_key = priv_key
        //     .public_key()
        //     .to_encoded_point(false)
        //     .as_bytes()
        //     .to_vec();
        let public_key = priv_key.public_key();
        // let der_public_key = publick_key.to_public_key_der().unwrap();
        // let principal_id: PrincipalId =
        // PrincipalId::new_self_authenticating(&der_public_key.as_bytes());
        // assert_eq!(public_key.len(), 65);
    }
}
