use frost_secp256k1_tr::*;
use rand::thread_rng;

#[test]
fn check_tweaked_signing_key() {
    let signing_key = SigningKey::deserialize([0xAA; 32]).unwrap();
    let untweaked_verifying_key = VerifyingKey::from(signing_key);

    let mut rng = thread_rng();
    let message = b"message";

    let untweaked_signature = signing_key.sign(&mut rng, &message);

    untweaked_verifying_key
        .verify(&message, &untweaked_signature)
        .expect("untweaked signature should be valid under untweaked verifying key");

    let bip32_key_path = key_path!(vk / 0 / 0);
    let signing_target = SigningTarget::new(
        &message,
        SigningParameters {
            tapscript_merkle_root: Some(vec![]),
            bip32_key_path: Some(bip32_key_path),
        },
    );

    let tweaked_signature = signing_key.sign(&mut rng, signing_target.clone());

    untweaked_verifying_key
        .verify(&message, &tweaked_signature)
        .expect_err("tweaked signature should not be valid under untweaked verifying key");

    let tweaked_verifying_key = untweaked_verifying_key.effective_key(signing_target.sig_params());
    tweaked_verifying_key
        .verify(&message, &tweaked_signature)
        .expect("tweaked signature should be valid under tweaked verifying key");

    // Derive the child verifying key from the group's xpub
    let child_verifying_key = {
        let xpub =
            bip32::ExtendedPubkey::new(&untweaked_verifying_key, bip32::NETWORK_VERSION_XPUB);
        let child_xpub = xpub.derive(bip32_key_path.as_ref()).unwrap();
        VerifyingKey::new(child_xpub.public_key)
    };

    // Verify the signature using only the tapscript_merkle_root and the child verifying key,
    // without knowing the group's top-level xpub or derivation path.
    let taproot_only_signing_target = SigningTarget::new(
        &message,
        SigningParameters {
            tapscript_merkle_root: Some(vec![]),
            bip32_key_path: None,
        },
    );
    child_verifying_key
        .verify(taproot_only_signing_target, &tweaked_signature)
        .expect(
            "tweaked signature should be valid under bip32 derived child key\
             when tapscript_merkle_root is provided",
        );
}

#[test]
fn check_tweaked_sign_with_dkg() {
    // Test with both tweaks
    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a BIP32 tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: None,
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a Taproot tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: None,
            },
        ),
    );
}

#[test]
fn check_tweaked_sign_with_dealer() {
    // Test with both tweaks
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a BIP32 tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: None,
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a Taproot tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<Secp256K1Sha256, _>(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: None,
            },
        ),
    );
}

#[test]
fn check_tweaked_sign_with_dealer_and_identifiers() {
    // Test with both tweaks
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Secp256K1Sha256,
        _,
    >(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a BIP32 tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Secp256K1Sha256,
        _,
    >(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: None,
                bip32_key_path: Some(key_path!(vk / 0 / 0)),
            },
        ),
    );

    // Test with only a Taproot tweak.
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        Secp256K1Sha256,
        _,
    >(
        thread_rng(),
        SigningTarget::new(
            b"message",
            SigningParameters {
                tapscript_merkle_root: Some(vec![]),
                bip32_key_path: None,
            },
        ),
    );
}
