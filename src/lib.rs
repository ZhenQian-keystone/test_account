pub mod error;
pub mod icp;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bip32::PublicKey;
    use bip39::{Language, Mnemonic};
    use candid::types::principal;

    use crate::icp::account_id::{self, AccountIdentifier, Subaccount};
    use crate::icp::key_manager::mnemonic_to_key;
    use crate::icp::principal_id::PrincipalId;
    #[test]
    fn test_from_mnemonic_to_principal_id() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(phrase, mnemonic.phrase());
        let priv_key: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
            mnemonic_to_key(&mnemonic).unwrap();
        let public_key: k256::elliptic_curve::PublicKey<k256::Secp256k1> = priv_key.public_key();
        let pub_key_vec = public_key.to_bytes().to_vec();
        assert_eq!(33, pub_key_vec.len());

        let principal_id = PrincipalId::new_self_authenticating(&pub_key_vec);
        assert_eq!(
            "4mkhq-zr6zt-3rf53-uvlpo-ju5n6-kjtc5-2h4qp-wg7ah-usa7g-lozrb-hqe",
            principal_id.0.to_text().as_str()
        )
    }

    #[test]
    fn test_principal_id_to_account_id() {
        let phrase = "athlete before original when anchor horse equal drift response square total busy aspect hill long virtual record mountain ginger hybrid urge oxygen siege elder";
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(phrase, mnemonic.phrase());
        let priv_key: k256::elliptic_curve::SecretKey<k256::Secp256k1> =
            mnemonic_to_key(&mnemonic).unwrap();
        let public_key: k256::elliptic_curve::PublicKey<k256::Secp256k1> = priv_key.public_key();
        let pub_key_vec = public_key.to_bytes().to_vec();
        assert_eq!(33, pub_key_vec.len());

        let principal_id: PrincipalId = PrincipalId::new_self_authenticating(&pub_key_vec);
        let sub_account = Subaccount::from(&principal_id.0);
        let account_id: AccountIdentifier =
            AccountIdentifier::new(principal_id.0, Some(sub_account));
        assert_eq!(
            "c45c16c22b961d0acc6ffb13602aed8a79729b9c484b300e94d9b16d4b71468a".to_string(),
            account_id.to_hex()
        )
    }

    #[test]
    fn test_from_principal_id_str_to_default_account_id() {
        let principal_id_str = "x5yp5-dodh4-iowuy-fxbwx-gfqzm-i47uv-zcz4f-4yt6x-gttnz-hdayq-6qe";
        let principal_id = PrincipalId::from_str(&principal_id_str).unwrap();
        let account_id: AccountIdentifier = AccountIdentifier::new(principal_id.0, None);
        assert_eq!(
            "d48e9d9af599e3692230478b9e0816b245d6a4ea8bf4fe9e5c7a5ba893f690c8".to_string(),
            account_id.to_hex()
        )
    }

    #[test]
    fn test_from_principal_id_str_to_default_account_id2() {
        let principal_id_str = "7rtqo-ah3ki-saurz-utzxq-o4yhl-so2yx-iardd-mktej-x4k24-ijen6-dae";
        let principal_id = PrincipalId::from_str(&principal_id_str).unwrap();
        let account_id: AccountIdentifier = AccountIdentifier::new(principal_id.0, None);
        assert_eq!(
            "33a807e6078195d2bbe1904b0ed0fc65b8a3a437b43831ccebba2b7b6d393bd6".to_string(),
            account_id.to_hex()
        )
    }
}
