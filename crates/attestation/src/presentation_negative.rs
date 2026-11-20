//! Test-only negative cases for TLSN presentation verification.
//!
//! `ZK/tlsn-integration/scripts/test-happy-path.sh` invokes these tests against
//! a real Mock Bank presentation. Each case tampers the serialized presentation
//! the way an attacker would, then asserts that TLSN rejects it at the intended
//! verification boundary instead of failing while deserializing the bytes.

use std::{env, fs, path::PathBuf};

use anyhow::{Context, ensure};

use crate::{Attestation, CryptoProvider, presentation::Presentation};
use tlsn_core::webpki::{CertificateDer, RootCertStore, ServerCertVerifier};

const EXPECTED_NOTARY_SIGNATURE_LEN: usize = 64;

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .with_context(|| format!("{name} is not set"))
}

fn presentation_bytes() -> anyhow::Result<Vec<u8>> {
    fs::read(required_path("TLSN_NEGATIVE_PRESENTATION")?)
        .context("failed to read the presentation under test")
}

fn provider_for_ca(path: PathBuf) -> anyhow::Result<CryptoProvider> {
    let ca_der = fs::read(&path)
        .with_context(|| format!("failed to read CA certificate {}", path.display()))?;
    Ok(CryptoProvider {
        cert: ServerCertVerifier::new(&RootCertStore {
            roots: vec![CertificateDer(ca_der)],
        })?,
        ..Default::default()
    })
}

fn trusted_provider() -> anyhow::Result<CryptoProvider> {
    provider_for_ca(required_path("TLSN_NEGATIVE_CA_DER")?)
}

fn untrusted_provider() -> anyhow::Result<CryptoProvider> {
    provider_for_ca(required_path("TLSN_NEGATIVE_UNTRUSTED_CA_DER")?)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn replace_same_length(
    haystack: &mut [u8],
    needle: &[u8],
    replacement: &[u8],
) -> anyhow::Result<()> {
    ensure!(
        needle.len() == replacement.len(),
        "replacement must keep the tampered value length"
    );
    let offset = find_subslice(haystack, needle).with_context(|| {
        format!(
            "expected value {:?} is not disclosed in the presentation",
            String::from_utf8_lossy(needle)
        )
    })?;
    haystack[offset..offset + needle.len()].copy_from_slice(replacement);
    Ok(())
}

fn expect_rejection(presentation: Presentation, provider: &CryptoProvider) -> String {
    match presentation.verify(provider) {
        Ok(_) => panic!("tampered presentation was accepted by TLSN verification"),
        Err(error) => error.to_string(),
    }
}

#[test]
#[ignore = "invoked by the outer Mock Bank integration test"]
fn presentation_negative_baseline_verifies() -> anyhow::Result<()> {
    let presentation: Presentation = bincode::deserialize(&presentation_bytes()?)
        .context("baseline presentation failed to deserialize")?;
    let output = presentation
        .verify(&trusted_provider()?)
        .context("baseline presentation was rejected")?;
    ensure!(
        output.server_name.is_some(),
        "baseline presentation does not authenticate a server name"
    );
    ensure!(
        output.transcript.is_some(),
        "baseline presentation does not disclose a transcript"
    );
    Ok(())
}

#[test]
#[ignore = "invoked by the outer Mock Bank integration test"]
fn presentation_negative_untrusted_ca() -> anyhow::Result<()> {
    let presentation: Presentation = bincode::deserialize(&presentation_bytes()?)
        .context("presentation failed to deserialize")?;
    let message = expect_rejection(presentation, &untrusted_provider()?);
    assert!(
        message.contains("server identity error"),
        "untrusted CA was rejected at the wrong boundary: {message}"
    );
    assert!(
        message.contains("certificate"),
        "untrusted CA was rejected for a reason other than the certificate chain: {message}"
    );
    Ok(())
}

#[test]
#[ignore = "invoked by the outer Mock Bank integration test"]
fn presentation_negative_tampered_attestation_signature() -> anyhow::Result<()> {
    let attestation: Attestation = bincode::deserialize(
        &fs::read(required_path("TLSN_NEGATIVE_ATTESTATION")?)
            .context("failed to read the attestation under test")?,
    )
    .context("failed to decode the attestation under test")?;
    let signature = attestation.signature.data;
    ensure!(
        signature.len() == EXPECTED_NOTARY_SIGNATURE_LEN,
        "unexpected notary signature length: {}",
        signature.len()
    );

    let mut bytes = presentation_bytes()?;
    let offset = find_subslice(&bytes, &signature)
        .context("the notary signature is not present in the presentation")?;
    bytes[offset + signature.len() - 1] ^= 1;

    let presentation: Presentation = bincode::deserialize(&bytes)
        .context("tampered presentation failed to deserialize; expected a verification failure")?;
    let message = expect_rejection(presentation, &trusted_provider()?);
    assert!(
        message.contains("attestation error"),
        "tampered notary signature was rejected at the wrong boundary: {message}"
    );
    Ok(())
}

#[test]
#[ignore = "invoked by the outer Mock Bank integration test"]
fn presentation_negative_tampered_disclosure_value() -> anyhow::Result<()> {
    let mut bytes = presentation_bytes()?;
    replace_same_length(&mut bytes, b"ACME Corporation", b"ACME CorporatioN")?;

    let presentation: Presentation = bincode::deserialize(&bytes)
        .context("tampered presentation failed to deserialize; expected a verification failure")?;
    let message = expect_rejection(presentation, &trusted_provider()?);
    assert!(
        message.contains("transcript error"),
        "tampered disclosed value was rejected at the wrong boundary: {message}"
    );
    Ok(())
}

#[test]
#[ignore = "invoked by the outer Mock Bank integration test"]
fn presentation_negative_tampered_response_status() -> anyhow::Result<()> {
    let mut bytes = presentation_bytes()?;
    replace_same_length(&mut bytes, b"200 OK", b"201 OK")?;

    let presentation: Presentation = bincode::deserialize(&bytes)
        .context("tampered presentation failed to deserialize; expected a verification failure")?;
    let message = expect_rejection(presentation, &trusted_provider()?);
    assert!(
        message.contains("transcript error"),
        "tampered response status was rejected at the wrong boundary: {message}"
    );
    Ok(())
}
