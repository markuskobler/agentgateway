use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use parking_lot::Mutex;
use secrecy::SecretString;

use super::AuthorizationLocation;
use super::jwt_signing::{
	CertificateHeader, CertificateHeaders, ParsedEncodingKey, load_certificate_headers,
	signing_header,
};
use super::oauth::SigningAlg;
use crate::resource_manager::{ResourceFetcher, ResourceRef};
use crate::serdes::FileOrInline;
use crate::*;

/// Default token lifetime. Keep signed tokens short-lived to limit replay
/// exposure; upstreams like Snowflake cap `exp` at one hour anyway.
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Backdate `iat` and extend `exp` by this amount so validators with slightly
/// skewed clocks do not reject freshly minted tokens, matching Google's auth
/// library behavior.
const CLOCK_SKEW_FUDGE: Duration = Duration::from_secs(10);

/// Refresh cached tokens before they are close enough to expiry to fail while
/// an upstream request is in flight.
const CACHE_SAFETY_MARGIN: Duration = Duration::from_secs(15);

/// Bound cache reuse so tokens are not served with stale `iat` claims. This is
/// independent of the configured `ttl`, which controls `exp`.
const MAX_TOKEN_AGE: Duration = Duration::from_secs(60);

/// Time-based claims the signer owns; user-configured claims must not collide
/// with these. `iat` and `exp` are always set by the signer. `nbf` is not
/// emitted (validators treat `iat` as the issue time and a static `nbf` makes
/// no sense for per-request tokens) but stays reserved.
const RESERVED_CLAIMS: &[&str] = &["iat", "exp", "nbf"];

/// Rounds a ttl up to the next whole second so a sub-second component (e.g.
/// 1500ms) never yields a shorter lifetime than configured, in both the
/// signed token and any serialized/debug representation of the config.
fn ttl_secs_ceil(ttl: Duration) -> u64 {
	ttl
		.as_secs()
		.saturating_add(u64::from(ttl.subsec_nanos() > 0))
}

/// The signing key, either parsed eagerly (inline PEM) or deferred to
/// [`JwtSignAuth::resolve`] (file paths), so file-based keys register with the
/// resource manager and reload when the file changes.
#[derive(Clone)]
enum PemSource {
	Inline(String),
	File(PathBuf),
}

impl From<FileOrInline> for PemSource {
	fn from(value: FileOrInline) -> Self {
		match value {
			FileOrInline::Inline(pem) => Self::Inline(pem),
			FileOrInline::File { file } => Self::File(file),
		}
	}
}

impl PemSource {
	async fn load(
		&self,
		resources: &ResourceFetcher,
		context: &'static str,
	) -> anyhow::Result<String> {
		match self {
			Self::Inline(pem) => Ok(pem.clone()),
			Self::File(path) => {
				let pem = resources
					.fetch(ResourceRef::File(path.clone()))
					.await
					.with_context(|| format!("failed to load jwtSign {context}"))?;
				String::from_utf8(pem.to_vec())
					.with_context(|| format!("jwtSign {context} is not valid UTF-8"))
			},
		}
	}
}

#[derive(Clone)]
enum SigningMaterial {
	Resolved {
		key: ParsedEncodingKey,
		certificate_headers: CertificateHeaders,
	},
	Deferred {
		signing_key: PemSource,
		certificate: Option<(PemSource, CertificateHeader)>,
	},
}

#[derive(Clone)]
struct CachedJwt {
	token: SecretString,
	reusable_until: u64,
}

#[derive(Clone, Default)]
struct JwtTokenCache(Arc<Mutex<Option<CachedJwt>>>);

impl JwtTokenCache {
	fn get_or_insert_with<E>(
		&self,
		now: u64,
		sign: impl FnOnce() -> Result<CachedJwt, E>,
	) -> Result<SecretString, E> {
		let mut entry = self.0.lock();
		if let Some(cached) = entry.as_ref()
			&& token_is_fresh(cached, now)
		{
			return Ok(cached.token.clone());
		}

		*entry = None;
		let signed = sign()?;
		let token = signed.token.clone();
		if token_is_fresh(&signed, now) {
			*entry = Some(signed);
		}
		Ok(token)
	}

	fn clear(&self) {
		*self.0.lock() = None;
	}
}

fn token_is_fresh(token: &CachedJwt, now: u64) -> bool {
	token.reusable_until.saturating_sub(now) > CACHE_SAFETY_MARGIN.as_secs()
}

fn token_reusable_until(iat: u64, exp: u64) -> u64 {
	exp.min(iat.saturating_add(MAX_TOKEN_AGE.as_secs()))
}

/// Supplies a short-lived JWT signed with a private key to the backend. Tokens
/// are reused until shortly before either expiry or the maximum token age.
#[derive(Clone, serde::Deserialize)]
#[serde(try_from = "RawJwtSignAuth", rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct JwtSignAuth {
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	signing_material: SigningMaterial,
	#[serde(default)]
	alg: SigningAlg,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	kid: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	certificate_header: Option<CertificateHeader>,
	claims: BTreeMap<String, serde_json::Value>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	ttl: Option<Duration>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub(super) location: Option<AuthorizationLocation>,
	#[serde(skip)]
	#[cfg_attr(feature = "schema", schemars(skip))]
	cache: JwtTokenCache,
}

impl fmt::Debug for JwtSignAuth {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("JwtSignAuth")
			.field("signing_material", &"<redacted>")
			.field("alg", &self.alg)
			.field("kid", &self.kid)
			.field("certificate_header", &self.certificate_header)
			.field("claims", &self.claims)
			.field("ttl", &self.ttl)
			.field("location", &self.location)
			.finish()
	}
}

impl serde::Serialize for JwtSignAuth {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		use serde::ser::SerializeStruct;

		let mut state = serializer.serialize_struct("JwtSignAuth", 6)?;
		state.serialize_field("alg", &self.alg)?;
		state.serialize_field("kid", &self.kid)?;
		state.serialize_field("certificateHeader", &self.certificate_header)?;
		state.serialize_field("claims", &self.claims)?;
		state.serialize_field(
			"ttl",
			&self.ttl.map(|ttl| format!("{}s", ttl_secs_ceil(ttl))),
		)?;
		state.serialize_field("location", &self.location)?;
		state.end()
	}
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
struct RawJwtSignAuth {
	/// PEM-encoded private signing key (RSA or EC, matching `alg`).
	#[cfg_attr(feature = "schema", schemars(with = "crate::serdes::FileOrInline"))]
	signing_key: FileOrInline,
	/// PEM-encoded X.509 certificate chain, leaf first. Required when
	/// `certificateHeader` is set.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::serdes::FileOrInline>")
	)]
	certificate: Option<FileOrInline>,
	/// Optional JWS certificate header. Required when `certificate` is set.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	certificate_header: Option<CertificateHeader>,
	/// JWS signing algorithm. Defaults to RS256.
	#[serde(default)]
	alg: SigningAlg,
	/// Optional JWS key ID header.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	kid: Option<String>,
	/// Static claims added to every token (e.g. iss, sub, aud). Values may be
	/// any JSON value (e.g. a string, number, bool, or array). `iat`, `exp`,
	/// and `nbf` are reserved for the signer and cannot be configured here.
	#[cfg_attr(feature = "schema", schemars(extend("minProperties" = 1)))]
	claims: BTreeMap<String, serde_json::Value>,
	/// Token lifetime used for `exp`. Defaults to 300s. Cache reuse is also
	/// bounded by the token's issue time and may be shorter than this lifetime.
	#[serde(
		default,
		with = "crate::serdes::serde_dur_option",
		skip_serializing_if = "Option::is_none"
	)]
	#[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
	ttl: Option<Duration>,
	/// Where the signed token is written. Defaults to the Authorization
	/// header with a `Bearer ` prefix.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	location: Option<AuthorizationLocation>,
}

impl TryFrom<RawJwtSignAuth> for JwtSignAuth {
	type Error = String;

	fn try_from(raw: RawJwtSignAuth) -> Result<Self, Self::Error> {
		validate_config(&raw.claims, raw.ttl, raw.location.as_ref())?;
		let certificate = match (raw.certificate, raw.certificate_header) {
			(Some(certificate), Some(header)) => Some((PemSource::from(certificate), header)),
			(Some(_), None) => {
				return Err("jwtSign certificateHeader is required when certificate is set".into());
			},
			(None, Some(_)) => {
				return Err("jwtSign certificate is required when certificateHeader is set".into());
			},
			(None, None) => None,
		};
		let signing_material = build_signing_material(raw.alg, raw.signing_key.into(), certificate)?;
		Ok(Self {
			signing_material,
			alg: raw.alg,
			kid: raw.kid,
			certificate_header: raw.certificate_header,
			claims: raw.claims,
			ttl: raw.ttl,
			location: raw.location,
			cache: JwtTokenCache::default(),
		})
	}
}

fn validate_config(
	claims: &BTreeMap<String, serde_json::Value>,
	ttl: Option<Duration>,
	location: Option<&AuthorizationLocation>,
) -> Result<(), String> {
	if claims.is_empty() {
		return Err("jwtSign requires at least one claim".into());
	}
	for reserved in RESERVED_CLAIMS {
		if claims.contains_key(*reserved) {
			return Err(format!(
				"jwtSign claim {reserved:?} is reserved for the signer and cannot be configured"
			));
		}
	}
	if let Some(ttl) = ttl
		&& ttl.as_secs() == 0
	{
		return Err("jwtSign ttl must be at least one second".into());
	}
	if matches!(location, Some(AuthorizationLocation::Expression(_))) {
		return Err(
			"jwtSign location cannot be an expression because signed tokens must be inserted into requests"
				.into(),
		);
	}
	Ok(())
}

fn parse_signing_key(alg: SigningAlg, pem: &str) -> Result<ParsedEncodingKey, String> {
	ParsedEncodingKey::parse(alg, pem.as_bytes())
		.map_err(|e| format!("failed to parse jwtSign signingKey: {e}"))
}

fn resolve_signing_material(
	alg: SigningAlg,
	signing_key_pem: &str,
	certificate: Option<(&str, CertificateHeader)>,
) -> Result<SigningMaterial, String> {
	let key = parse_signing_key(alg, signing_key_pem.trim())?;
	let certificate_headers = match certificate {
		Some((certificate_pem, header)) => {
			load_certificate_headers(certificate_pem.trim(), header, signing_key_pem.trim())?
		},
		None => CertificateHeaders::default(),
	};
	Ok(SigningMaterial::Resolved {
		key,
		certificate_headers,
	})
}

fn build_signing_material(
	alg: SigningAlg,
	signing_key: PemSource,
	certificate: Option<(PemSource, CertificateHeader)>,
) -> Result<SigningMaterial, String> {
	match (&signing_key, &certificate) {
		(PemSource::Inline(signing_key_pem), None) => {
			resolve_signing_material(alg, signing_key_pem, None)
		},
		(PemSource::Inline(signing_key_pem), Some((PemSource::Inline(certificate_pem), header))) => {
			resolve_signing_material(alg, signing_key_pem, Some((certificate_pem, *header)))
		},
		_ => Ok(SigningMaterial::Deferred {
			signing_key,
			certificate,
		}),
	}
}

impl JwtSignAuth {
	pub fn try_new(
		signing_key_pem: &str,
		alg: SigningAlg,
		kid: Option<String>,
		claims: BTreeMap<String, serde_json::Value>,
		ttl: Option<Duration>,
		location: Option<AuthorizationLocation>,
	) -> Result<Self, String> {
		Self::try_new_with_certificate(signing_key_pem, alg, kid, claims, ttl, location, None)
	}

	pub(crate) fn try_new_with_certificate(
		signing_key_pem: &str,
		alg: SigningAlg,
		kid: Option<String>,
		claims: BTreeMap<String, serde_json::Value>,
		ttl: Option<Duration>,
		location: Option<AuthorizationLocation>,
		certificate: Option<(&str, CertificateHeader)>,
	) -> Result<Self, String> {
		validate_config(&claims, ttl, location.as_ref())?;
		let certificate_header = certificate.map(|(_, header)| header);
		let signing_material = resolve_signing_material(alg, signing_key_pem, certificate)?;
		Ok(Self {
			signing_material,
			alg,
			kid,
			certificate_header,
			claims,
			ttl,
			location,
			cache: JwtTokenCache::default(),
		})
	}

	/// Resolves file-backed signing material through the resource manager so
	/// key or certificate changes trigger a config reload.
	pub async fn resolve(&mut self, resources: &ResourceFetcher) -> anyhow::Result<()> {
		let SigningMaterial::Deferred {
			signing_key,
			certificate,
		} = self.signing_material.clone()
		else {
			return Ok(());
		};
		let signing_key_pem = signing_key.load(resources, "signingKey").await?;
		let certificate_pem = match &certificate {
			Some((source, header)) => Some((source.load(resources, "certificate").await?, *header)),
			None => None,
		};
		self.signing_material = resolve_signing_material(
			self.alg,
			&signing_key_pem,
			certificate_pem
				.as_ref()
				.map(|(pem, header)| (pem.as_str(), *header)),
		)
		.map_err(anyhow::Error::msg)?;
		self.cache.clear();
		Ok(())
	}

	pub(super) fn token(&self) -> anyhow::Result<SecretString> {
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.context("system clock is before the unix epoch")?
			.as_secs();
		self.cache.get_or_insert_with(now, || self.sign_at(now))
	}

	fn sign_at(&self, now: u64) -> anyhow::Result<CachedJwt> {
		let SigningMaterial::Resolved {
			key: signing_key,
			certificate_headers,
		} = &self.signing_material
		else {
			anyhow::bail!("jwtSign file-backed signing material was not resolved at config load");
		};
		let ttl = self.ttl.unwrap_or(DEFAULT_TTL);
		let skew = CLOCK_SKEW_FUDGE.as_secs();

		let mut claims = serde_json::Map::with_capacity(self.claims.len() + RESERVED_CLAIMS.len());
		for (key, value) in &self.claims {
			claims.insert(key.clone(), value.clone());
		}
		let iat = now.saturating_sub(skew);
		let exp = now
			.checked_add(skew)
			.and_then(|t| t.checked_add(ttl_secs_ceil(ttl)))
			.context("jwtSign ttl overflows the exp timestamp")?;
		claims.insert("iat".to_string(), iat.into());
		claims.insert("exp".to_string(), exp.into());

		let header = signing_header(
			self.alg,
			self.kid.clone(),
			certificate_headers.x5c.clone(),
			certificate_headers.x5t_s256.clone(),
		);
		let token = signing_key
			.encode(&header, &serde_json::Value::Object(claims))
			.context("failed to sign backend JWT")?;
		Ok(CachedJwt {
			token: token.into(),
			reusable_until: token_reusable_until(iat, exp),
		})
	}
}

#[cfg(test)]
mod cache_tests {
	use std::convert::Infallible;
	use std::sync::Barrier;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use secrecy::ExposeSecret;

	use super::*;

	fn cached(token: &str, reusable_until: u64) -> CachedJwt {
		CachedJwt {
			token: token.to_string().into(),
			reusable_until,
		}
	}

	#[test]
	fn reuse_deadline_is_bounded_by_expiration_and_token_age() {
		assert_eq!(token_reusable_until(100, 120), 120);
		assert_eq!(token_reusable_until(100, 1000), 160);
	}

	#[test]
	fn ttl_rounding_saturates_at_the_duration_limit() {
		assert_eq!(ttl_secs_ceil(Duration::new(u64::MAX, 1)), u64::MAX);
	}

	#[test]
	fn cache_is_shared_across_clones_and_refreshes_near_expiry() {
		let cache = JwtTokenCache::default();
		let calls = AtomicUsize::new(0);
		let first = cache
			.get_or_insert_with(100, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("first", 200))
			})
			.unwrap();
		let hit = cache
			.clone()
			.get_or_insert_with(184, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("unexpected", 300))
			})
			.unwrap();
		let refreshed = cache
			.get_or_insert_with(185, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("second", 300))
			})
			.unwrap();

		assert_eq!(first.expose_secret(), "first");
		assert_eq!(hit.expose_secret(), "first");
		assert_eq!(refreshed.expose_secret(), "second");
		assert_eq!(calls.load(Ordering::Relaxed), 2);
	}

	#[test]
	fn short_lived_tokens_and_errors_are_not_cached() {
		let cache = JwtTokenCache::default();
		let calls = AtomicUsize::new(0);
		for _ in 0..2 {
			cache
				.get_or_insert_with(100, || {
					calls.fetch_add(1, Ordering::Relaxed);
					Ok::<_, Infallible>(cached("short", 115))
				})
				.unwrap();
		}
		assert_eq!(calls.load(Ordering::Relaxed), 2);

		let attempts = AtomicUsize::new(0);
		for _ in 0..2 {
			let result = cache.get_or_insert_with(100, || {
				attempts.fetch_add(1, Ordering::Relaxed);
				Err::<CachedJwt, _>("signing failed")
			});
			assert_eq!(result.unwrap_err(), "signing failed");
		}
		assert_eq!(attempts.load(Ordering::Relaxed), 2);
	}

	#[test]
	fn concurrent_misses_sign_once() {
		const WORKERS: usize = 8;
		let cache = JwtTokenCache::default();
		let calls = Arc::new(AtomicUsize::new(0));
		let barrier = Arc::new(Barrier::new(WORKERS));
		let workers = (0..WORKERS)
			.map(|_| {
				let cache = cache.clone();
				let calls = Arc::clone(&calls);
				let barrier = Arc::clone(&barrier);
				std::thread::spawn(move || {
					barrier.wait();
					cache
						.get_or_insert_with(100, || {
							calls.fetch_add(1, Ordering::Relaxed);
							Ok::<_, Infallible>(cached("shared", 160))
						})
						.unwrap()
				})
			})
			.collect::<Vec<_>>();

		for worker in workers {
			assert_eq!(worker.join().unwrap().expose_secret(), "shared");
		}
		assert_eq!(calls.load(Ordering::Relaxed), 1);
	}

	#[test]
	fn cache_refreshes_at_reuse_deadline() {
		let cache = JwtTokenCache::default();
		let calls = AtomicUsize::new(0);
		let first = cache
			.get_or_insert_with(100, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("first", 150))
			})
			.unwrap();
		let hit = cache
			.get_or_insert_with(134, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("unexpected", 194))
			})
			.unwrap();
		let refreshed = cache
			.get_or_insert_with(135, || {
				calls.fetch_add(1, Ordering::Relaxed);
				Ok::<_, Infallible>(cached("second", 195))
			})
			.unwrap();

		assert_eq!(first.expose_secret(), "first");
		assert_eq!(hit.expose_secret(), "first");
		assert_eq!(refreshed.expose_secret(), "second");
		assert_eq!(calls.load(Ordering::Relaxed), 2);
	}
}
