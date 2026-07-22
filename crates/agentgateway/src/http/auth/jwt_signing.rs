use std::fmt;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{apply, schema_enum};

#[apply(schema_enum!)]
pub enum CertificateHeader {
	/// Send the X.509 certificate chain in `x5c`.
	#[serde(rename = "x5c")]
	X5c,
	/// Send the leaf certificate's SHA-256 thumbprint in `x5t#S256`.
	#[serde(rename = "x5t#S256")]
	X5tS256,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum SigningAlg {
	#[default]
	#[serde(rename = "RS256")]
	Rs256,
	#[serde(rename = "RS384")]
	Rs384,
	#[serde(rename = "RS512")]
	Rs512,
	#[serde(rename = "PS256")]
	Ps256,
	#[serde(rename = "ES256")]
	Es256,
	#[serde(rename = "ES384")]
	Es384,
}

impl SigningAlg {
	fn algorithm(self) -> Algorithm {
		match self {
			Self::Rs256 => Algorithm::RS256,
			Self::Rs384 => Algorithm::RS384,
			Self::Rs512 => Algorithm::RS512,
			Self::Ps256 => Algorithm::PS256,
			Self::Es256 => Algorithm::ES256,
			Self::Es384 => Algorithm::ES384,
		}
	}
}

pub(crate) struct ParsedEncodingKey(EncodingKey);

impl ParsedEncodingKey {
	pub(crate) fn parse(alg: SigningAlg, pem: &[u8]) -> anyhow::Result<Self> {
		let key = match alg {
			SigningAlg::Rs256 | SigningAlg::Rs384 | SigningAlg::Rs512 | SigningAlg::Ps256 => {
				EncodingKey::from_rsa_pem(pem).context("failed to load RSA signing key")?
			},
			SigningAlg::Es256 | SigningAlg::Es384 => {
				EncodingKey::from_ec_pem(pem).context("failed to load EC signing key")?
			},
		};
		Ok(Self(key))
	}

	pub(crate) fn encode<T: serde::Serialize>(
		&self,
		header: &Header,
		claims: &T,
	) -> jsonwebtoken::errors::Result<String> {
		jsonwebtoken::encode(header, claims, &self.0)
	}
}

impl Clone for ParsedEncodingKey {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

impl fmt::Debug for ParsedEncodingKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("<redacted>")
	}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CertificateHeaders {
	pub(crate) x5c: Option<Vec<String>>,
	pub(crate) x5t_s256: Option<String>,
}

pub(crate) fn signing_header(
	alg: SigningAlg,
	kid: Option<String>,
	x5c: Option<Vec<String>>,
	x5t_s256: Option<String>,
) -> Header {
	let mut header = Header::new(alg.algorithm());
	header.kid = kid;
	header.x5c = x5c;
	header.x5t_s256 = x5t_s256;
	header
}

pub(crate) fn load_certificate_headers(
	certificate_pem: &str,
	certificate_header: CertificateHeader,
	signing_key_pem: &str,
) -> Result<CertificateHeaders, String> {
	let certificates = pem::parse_many(certificate_pem)
		.map_err(|e| format!("failed to parse JWT signing certificate: {e}"))?;
	let leaf = certificates
		.first()
		.ok_or_else(|| "failed to parse JWT signing certificate: no PEM blocks found".to_string())?;

	for certificate in &certificates {
		if certificate.tag() != "CERTIFICATE" {
			return Err(format!(
				"failed to parse JWT signing certificate: expected CERTIFICATE PEM block, found {}",
				certificate.tag()
			));
		}
		x509_parser::parse_x509_certificate(certificate.contents())
			.map_err(|e| format!("failed to parse JWT signing certificate: {e}"))?;
	}

	warn_if_certificate_key_mismatch(signing_key_pem, leaf.contents());

	Ok(match certificate_header {
		CertificateHeader::X5c => CertificateHeaders {
			x5c: Some(
				certificates
					.into_iter()
					.map(|certificate| STANDARD.encode(certificate.contents()))
					.collect(),
			),
			x5t_s256: None,
		},
		CertificateHeader::X5tS256 => CertificateHeaders {
			x5c: None,
			x5t_s256: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(leaf.contents()))),
		},
	})
}

fn warn_if_certificate_key_mismatch(signing_key_pem: &str, leaf_certificate_der: &[u8]) {
	match certificate_key_matches(signing_key_pem, leaf_certificate_der) {
		Ok(true) => {},
		Ok(false) => warn!("JWT signing certificate public key does not match signing key"),
		Err(error) => {
			warn!(%error, "unable to compare JWT signing certificate public key with signing key");
		},
	}
}

fn certificate_key_matches(
	signing_key_pem: &str,
	leaf_certificate_der: &[u8],
) -> Result<bool, String> {
	let signing_key = PrivateKeyDer::from_pem_slice(signing_key_pem.as_bytes())
		.map_err(|e| format!("failed to validate signing key against certificate: {e}"))?;
	let signing_key = crate::transport::tls::provider()
		.key_provider
		.load_private_key(signing_key)
		.map_err(|e| format!("failed to validate signing key against certificate: {e}"))?;
	let signing_key_spki = signing_key.public_key().ok_or_else(|| {
		"failed to validate signing key against certificate: public key is unavailable".to_string()
	})?;
	let (_, certificate) = x509_parser::parse_x509_certificate(leaf_certificate_der)
		.map_err(|e| format!("failed to parse JWT signing certificate: {e}"))?;
	Ok(signing_key_spki.as_ref() == certificate.public_key().raw)
}
