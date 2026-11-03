use std::{env, fs, path::PathBuf};

use anyhow::{Context, ensure};
use serde_json::{Value, json};

use crate::{
    Attestation, CryptoProvider, Secrets,
    serialize::{CanonicalSerialize, DomainSeparator},
    signing::{Secp256k1Signer, Signer},
};
use tlsn_core::{
    hash::HashAlgId,
    merkle::MerkleTree,
    transcript::{Direction, TranscriptCommitment, TranscriptSecret},
};

#[test]
#[ignore = "invoked by the outer Mock Bank Noir fixture integration test"]
fn export_real_tlsn_income_fixture() -> anyhow::Result<()> {
    let attestation_path = required_path("TLSN_FIXTURE_ATTESTATION")?;
    let secrets_path = required_path("TLSN_FIXTURE_SECRETS")?;
    let output_path = required_path("TLSN_FIXTURE_OUTPUT")?;
    let expected_income = env::var("TLSN_FIXTURE_EXPECTED_INCOME")
        .context("TLSN_FIXTURE_EXPECTED_INCOME is not set")?
        .into_bytes();

    let attestation: Attestation = bincode::deserialize(&fs::read(attestation_path)?)
        .context("failed to decode the TLSN attestation")?;
    let secrets: Secrets =
        bincode::deserialize(&fs::read(secrets_path)?).context("failed to decode TLSN secrets")?;

    let fixture = build_fixture(&attestation, &secrets, &expected_income)?;
    assert_eq!(fixture["schema"], "zk-escrow.tlsn-income-fixture/v1");
    assert_eq!(fixture["income"]["bytes"], json!(expected_income));
    assert_eq!(fixture["income"]["direction"], "Received");
    assert_eq!(fixture["income"]["hash_alg"], "BLAKE3");
    assert_eq!(fixture["income"]["blinder"].as_array().unwrap().len(), 16);
    assert_eq!(
        fixture["income"]["commitment"].as_array().unwrap().len(),
        32
    );
    assert!(
        !fixture["attestation"]["header_bcs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture["attestation"]["body_root"]
            .as_array()
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        fixture["attestation"]["signature"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert!(
        !fixture["attestation"]["notary_verifying_key"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!fixture["income"]["leaf_bcs"].as_array().unwrap().is_empty());
    assert_eq!(fixture["income"]["leaf_hash"].as_array().unwrap().len(), 32);
    assert!(fixture["merkle"]["proof"]["leaf_count"].as_u64().unwrap() > 1);
    assert!(
        !fixture["merkle"]["proof"]["proof"]["proof_hashes"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let output_parent = fs::canonicalize(
        output_path
            .parent()
            .context("fixture output path has no parent directory")?,
    )?;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository_root = manifest_dir
        .ancestors()
        .nth(4)
        .context("could not resolve repository root from the attestation crate")?;
    let repository_root = fs::canonicalize(repository_root)?;
    ensure!(
        !output_parent.starts_with(&repository_root),
        "TLSN fixture output must be outside the repository checkout"
    );
    fs::write(&output_path, serde_json::to_vec_pretty(&fixture)?)?;
    println!("Exported a real TLSN fixture to {}", output_path.display());
    Ok(())
}

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("{name} is not set"))
}

fn build_fixture(
    attestation: &Attestation,
    secrets: &Secrets,
    expected_income: &[u8],
) -> anyhow::Result<Value> {
    let transcript = secrets.transcript();
    let received = transcript.received();
    let mut matches = Vec::new();

    for field in &attestation.body.transcript_commitments {
        let TranscriptCommitment::Hash(plaintext_hash) = &field.data else {
            continue;
        };
        if plaintext_hash.direction != Direction::Received {
            continue;
        }

        let start = plaintext_hash
            .idx
            .min()
            .context("transcript commitment has no start index")?;
        let end = plaintext_hash
            .idx
            .end()
            .context("transcript commitment has no end index")?;
        if received.get(start..end) == Some(expected_income) {
            matches.push((field, plaintext_hash, start, end));
        }
    }
    ensure!(
        matches.len() == 1,
        "expected exactly one received commitment matching monthly_income, found {}",
        matches.len()
    );
    let (income_field, plaintext_hash, start, end) = matches[0];

    let matching_secret = secrets
        .transcript_commitment_secrets
        .iter()
        .find_map(|secret| match secret {
            TranscriptSecret::Hash(hash_secret)
                if hash_secret.direction == Direction::Received
                    && hash_secret.idx.min() == Some(start)
                    && hash_secret.idx.end() == Some(end) =>
            {
                Some(hash_secret)
            }
            _ => None,
        })
        .context("matching TLSN transcript commitment blinder was not found")?;

    ensure!(
        plaintext_hash.hash.alg == HashAlgId::BLAKE3
            && matching_secret.alg == HashAlgId::BLAKE3
            && attestation.header.root.alg == HashAlgId::BLAKE3,
        "Mock Bank fixture uses an unexpected TLSN hash algorithm"
    );
    let provider = CryptoProvider::default();
    let hasher = provider.hash.get(&HashAlgId::BLAKE3)?;
    let plaintext_opening =
        hasher.hash_prefixed(expected_income, matching_secret.blinder.as_bytes());
    ensure!(
        plaintext_opening == plaintext_hash.hash.value,
        "monthly_income bytes and blinder do not open the TLSN commitment"
    );

    let bcs_commitment = income_field.data.serialize();
    let field_domain = income_field.data.domain();
    let body_fields = attestation.body.hash_fields(hasher);
    let field_id = income_field.id.0 as usize;
    let leaf_hash = body_fields
        .iter()
        .find(|(id, _)| id.0 as usize == field_id)
        .map(|(_, hash)| *hash)
        .context("monthly_income commitment is absent from the TLSN body hash fields")?;

    let mut merkle_tree = MerkleTree::new(hasher.id());
    let leaves = body_fields.iter().map(|(_, hash)| *hash).collect();
    merkle_tree.insert(hasher, leaves);
    ensure!(
        merkle_tree.root() == attestation.header.root,
        "recomputed TLSN body root differs from the signed header"
    );
    let merkle_proof = merkle_tree.proof(&[field_id]);
    merkle_proof.verify(hasher, &attestation.header.root, [(field_id, leaf_hash)])?;

    let header_bcs = attestation.header.serialize();
    let signature_verifier = provider.signature.get(&attestation.signature.alg)?;
    signature_verifier.verify(
        attestation.body.verifying_key(),
        &header_bcs,
        &attestation.signature.data,
    )?;

    // The local Mock Bank example intentionally uses a test-only notary key.
    let test_notary = Secp256k1Signer::new(&[1u8; 32])?;
    let pinned_test_key = test_notary.verifying_key();
    ensure!(
        attestation.body.verifying_key() == &pinned_test_key,
        "fixture notary key differs from the pinned Mock Bank test key"
    );

    let fixture = json!({
        "schema": "zk-escrow.tlsn-income-fixture/v1",
        "income": {
            "direction": "Received",
            "range": { "start": start, "end": end },
            "hash_alg": "BLAKE3",
            "bytes": expected_income,
            "blinder": matching_secret.blinder.as_bytes(),
            "commitment": plaintext_hash.hash.value.as_bytes(),
            "commitment_bcs": bcs_commitment,
            "field_id": field_id,
            "field_domain": field_domain,
            "leaf_bcs": bcs_commitment,
            "leaf_hash": leaf_hash.as_bytes(),
        },
        "attestation": {
            "header_bcs": header_bcs,
            "body_bcs": bcs::to_bytes(&attestation.body)?,
            "body_root_alg": "BLAKE3",
            "body_root": attestation.header.root.value.as_bytes(),
            "signature_alg": attestation.signature.alg.to_string(),
            "signature": attestation.signature.data,
            "notary_verifying_key_alg": pinned_test_key.alg.to_string(),
            "notary_verifying_key": pinned_test_key.data,
        },
        "merkle": {
            "proof": serde_json::to_value(&merkle_proof)?,
        },
    });
    Ok(fixture)
}
