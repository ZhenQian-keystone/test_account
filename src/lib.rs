pub mod error;
pub mod icp;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bip32::{PrivateKey, PublicKey};
    use bip39::{Language, Mnemonic};
    use bitcoin::secp256k1::{ecdsa, SecretKey};
    use candid::types::principal;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sec1::der::Encode;
    use serde::Serialize;

    use crate::icp::account_id::{self, AccountIdentifier, Subaccount};
    use crate::icp::key_manager::mnemonic_to_key;
    use crate::icp::principal_id::PrincipalId;

    #[test]
    fn test_public_key_vec_to_principal_id() {
        let pub_key_vec: [u8; 32] = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let principal_id: PrincipalId = PrincipalId::new_self_authenticating(&pub_key_vec);
        assert_eq!(
            "bngem-gzprz-dtr6o-xnali-fgmfi-fjgpb-rya7j-x2idk-3eh6u-4v7tx-hqe".to_string(),
            principal_id.to_string()
        );
    }

    #[test]
    fn test_public_key_to_principal_id() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(phrase, mnemonic.phrase());
        let priv_key = mnemonic_to_key(&mnemonic).unwrap();
        let public_key = priv_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(public_key.len(), 65);
        let principal_id: PrincipalId = PrincipalId::new_self_authenticating(&public_key);

        assert_ne!(
            "7rtqo-ah3ki-saurz-utzxq-o4yhl-so2yx-iardd-mktej-x4k24-ijen6-dae".to_string(),
            principal_id.to_string()
        );
    }
    #[test]
    fn test_from_principal_id_str_to_default_account_id() {
        let principal_id_str = "7rtqo-ah3ki-saurz-utzxq-o4yhl-so2yx-iardd-mktej-x4k24-ijen6-dae";
        let principal_id = PrincipalId::from_str(&principal_id_str).unwrap();
        let account_id: AccountIdentifier = AccountIdentifier::new(principal_id.0, None);
        assert_eq!(
            "33a807e6078195d2bbe1904b0ed0fc65b8a3a437b43831ccebba2b7b6d393bd6".to_string(),
            account_id.to_hex()
        )
    }
}
