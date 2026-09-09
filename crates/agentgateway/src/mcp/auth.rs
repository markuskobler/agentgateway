use axum::http::StatusCode;
use axum::response::Response;
use axum_core::response::IntoResponse;
use bytes::Bytes;
use http::Method;
use secrecy::ExposeSecret;
use tracing::{debug, warn};

use crate::http::jwt::Jwt;
use crate::http::*;
use crate::json::from_body_with_limit;
use crate::mcp::identity::{McpEndpoint, ResolvedMcpIdentity, is_discovery_candidate};
use crate::mcp::provider::McpProviderProfile;
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
#[cfg(test)]
use crate::types::agent::McpIDP;
use crate::types::agent::{McpAuthentication, McpResourceParameterMode};

pub(super) async fn apply_token_validation(
	req: &mut Request,
	auth: &McpAuthentication,
	validator: &Jwt,
	mut log: Option<&mut crate::telemetry::log::RequestLog>,
) -> Result<(), ProxyError> {
	debug!(
		"MCP auth configured; validating Authorization header (mode={:?})",
		auth.mode
	);
	let revalidated = validator.apply_retained_credential(log.as_deref_mut(), req);
	let validation = match revalidated {
		Ok(true) => Ok(()),
		// An earlier JWT policy consumed the credential, so MCP-specific requirements can no
		// longer be checked against it. Fail closed instead of trusting claims we did not verify.
		Ok(false) if validator.credential_was_consumed(req) => {
			let err = ProxyError::ProcessingString(
				"MCP authentication configured but the token was already validated and stripped by an earlier policy; set preserveToken on that policy".to_string(),
			);
			return Err(create_auth_required_response(err, req, auth));
		},
		// No credential to validate, and no earlier policy took one: the configured mode decides.
		Ok(false) => validator.apply(log, req).await,
		Err(err) => Err(err),
	};
	validation.map_err(|e| {
		create_auth_required_response(ProxyError::JwtAuthenticationFailure(e), req, auth)
	})?;
	Ok(())
}

pub(crate) async fn enforce_authentication(
	req: &mut Request,
	auth: &McpAuthentication,
	validator: &Jwt,
	log: Option<&mut crate::telemetry::log::RequestLog>,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	let identity = ResolvedMcpIdentity::resolve(req, auth).map_err(ProxyError::ProcessingString)?;
	if let Some(endpoint) = identity.endpoint(req, auth.provider.as_ref()) {
		return handle_owned_endpoint(req, auth, &identity, endpoint, client).await;
	}
	if is_discovery_candidate(req.uri().path()) {
		return Ok(Some(StatusCode::NOT_FOUND.into_response()));
	}
	apply_token_validation(req, auth, validator, log).await?;
	Ok(None)
}

async fn handle_owned_endpoint(
	req: &mut Request,
	auth: &McpAuthentication,
	identity: &ResolvedMcpIdentity,
	endpoint: McpEndpoint,
	client: &PolicyClient,
) -> Result<Option<Response>, ProxyError> {
	if !endpoint.accepts(req.method()) {
		return Ok(Some(
			Response::builder()
				.status(StatusCode::METHOD_NOT_ALLOWED)
				.header(::http::header::ALLOW, endpoint.allowed_methods())
				.body(Body::empty())?,
		));
	}
	if req.method() == Method::OPTIONS {
		return Ok(Some(
			Response::builder()
				.status(StatusCode::NO_CONTENT)
				.header(::http::header::ALLOW, endpoint.allowed_methods())
				.body(Body::empty())?,
		));
	}
	if matches!(endpoint, McpEndpoint::Authorization | McpEndpoint::Token)
		&& !McpProviderProfile::new(auth.provider.as_ref()).proxies_oauth_endpoints()
	{
		return Ok(Some(StatusCode::NOT_FOUND.into_response()));
	}

	match endpoint {
		McpEndpoint::Registration => Ok(Some(
			client_registration(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("client_registration error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		McpEndpoint::ProtectedResourceMetadata => Ok(Some(
			protected_resource_metadata(auth, identity)
				.await
				.into_response(),
		)),
		// Provider adapters own these endpoints and apply their declared resource handling
		// before forwarding to the upstream authorization server.
		McpEndpoint::Authorization => Ok(Some(
			oauth_authorize(req, auth)
				.map_err(|e| {
					warn!("OAuth authorize adapter error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		McpEndpoint::Token => Ok(Some(
			oauth_token(req, auth, client.clone())
				.await
				.map_err(|e| {
					warn!("OAuth token adapter error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
		McpEndpoint::AuthorizationServerMetadata => Ok(Some(
			authorization_server_metadata(auth, identity, client.clone())
				.await
				.map_err(|e| {
					warn!("authorization_server_metadata error: {}", e);
					StatusCode::INTERNAL_SERVER_ERROR
				})
				.into_response(),
		)),
	}
}

pub(crate) fn create_auth_required_response(
	inner: ProxyError,
	req: &Request,
	auth: &McpAuthentication,
) -> ProxyError {
	let www_authenticate_value = ResolvedMcpIdentity::resolve(req, auth)
		.map(|identity| {
			format!(
				"Bearer resource_metadata=\"{}\"",
				identity.protected_resource_metadata_url()
			)
		})
		.unwrap_or_else(|_| "Bearer".to_string());

	ProxyError::McpJwtAuthenticationFailure(Box::new(inner), www_authenticate_value)
}

pub(super) async fn protected_resource_metadata(
	auth: &McpAuthentication,
	identity: &ResolvedMcpIdentity,
) -> Response {
	let json_body = auth.resource_metadata.to_rfc_json(
		identity.public_resource.to_string(),
		identity.public_authorization_server.to_string(),
	);

	::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&json_body).unwrap_or_default(),
		)))
		.unwrap_or_else(|_| {
			::http::Response::builder()
				.status(StatusCode::INTERNAL_SERVER_ERROR)
				.body(axum::body::Body::empty())
				.unwrap()
		})
}

pub(super) async fn authorization_server_metadata(
	auth: &McpAuthentication,
	identity: &ResolvedMcpIdentity,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	debug!(
		public_resource = %identity.public_resource,
		public_authorization_server = %identity.public_authorization_server,
		upstream_discovery_issuer = %identity.upstream_discovery_issuer,
		expected_token_issuer = %identity.expected_token_issuer,
		metadata_url = %identity.authorization_server_metadata_url(),
		authorization_url = %identity.authorization_url(),
		token_url = %identity.token_url(),
		registration_url = %identity.registration_url(),
		"serving MCP authorization server metadata"
	);
	let provider = McpProviderProfile::new(auth.provider.as_ref());
	let metadata_uri = provider
		.metadata_url(identity.upstream_discovery_issuer.as_str())
		.map_err(ProxyError::ProcessingString)?;
	let ureq = ::http::Request::builder()
		.uri(metadata_uri)
		.body(Body::empty())?;
	let upstream = client
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
		.simple_call(ureq)
		.await?;
	if !upstream.status().is_success() {
		return Err(ProxyError::ProcessingString(format!(
			"upstream authorization server metadata returned {}",
			upstream.status()
		)));
	}
	let limit = crate::http::response_buffer_limit(&upstream);
	let mut resp: serde_json::Value = from_body_with_limit(upstream.into_body(), limit)
		.await
		.map_err(ProxyError::Body)?;
	provider
		.rewrite_metadata(
			&mut resp,
			identity
				.public_authorization_server
				.as_str()
				.trim_end_matches('/'),
			&auth.audiences,
			auth.client_id.is_some(),
		)
		.map_err(ProxyError::ProcessingString)?;
	if provider.rewrites_public_issuer() {
		let object = resp.as_object_mut().ok_or_else(|| {
			ProxyError::ProcessingString(
				"authorization server metadata must be a JSON object".to_string(),
			)
		})?;
		object.insert(
			"issuer".to_string(),
			serde_json::Value::String(identity.public_authorization_server.to_string()),
		);
	}

	let response = ::http::Response::builder()
		.status(StatusCode::OK)
		.header("content-type", "application/json")
		.body(axum::body::Body::from(Bytes::from(
			serde_json::to_string(&resp).map_err(|e| ProxyError::Body(crate::http::Error::new(e)))?,
		)))?;

	Ok(response)
}

pub(super) async fn client_registration(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	if let Some(client_id) = &auth.client_id {
		return build_mock_dcr_response(req, client_id).await;
	}

	let body = std::mem::take(req.body_mut());
	let content_type = req.headers().get(::http::header::CONTENT_TYPE).cloned();
	let authorization = req.headers().get(::http::header::AUTHORIZATION).cloned();
	let registration_uri = McpProviderProfile::new(auth.provider.as_ref())
		.registration_url(auth.upstream_issuer.as_deref().unwrap_or(&auth.issuer))
		.map_err(ProxyError::ProcessingString)?;
	let mut builder = ::http::Request::builder()
		.uri(registration_uri)
		.method(Method::POST);
	if let Some(content_type) = content_type {
		builder = builder.header(::http::header::CONTENT_TYPE, content_type);
	}
	if let Some(authorization) = authorization {
		builder = builder.header(::http::header::AUTHORIZATION, authorization);
	}
	let ureq = builder.body(body)?;

	let upstream = client
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
		.simple_call(ureq)
		.await?;

	Ok(upstream)
}

/// Redirect a gateway-owned authorization request to the provider's authorization endpoint.
pub(super) fn oauth_authorize(
	req: &Request,
	auth: &McpAuthentication,
) -> Result<Response, ProxyError> {
	let provider = McpProviderProfile::new(auth.provider.as_ref());
	let authorization_endpoint = provider
		.authorization_endpoint(auth.upstream_issuer.as_deref().unwrap_or(&auth.issuer))
		.map_err(ProxyError::ProcessingString)?
		.ok_or_else(|| {
			ProxyError::ProcessingString("provider has no proxied authorize endpoint".into())
		})?;
	let mut location = url::Url::parse(&authorization_endpoint)
		.map_err(|e| ProxyError::ProcessingString(format!("invalid authorize URL: {e}")))?;
	let query = req.uri().query().unwrap_or_default();
	let mut pairs = url::form_urlencoded::parse(query.as_bytes())
		.filter(|(key, _)| !(provider.strips_resource_parameter() && key == "resource"))
		.map(|(key, value)| (key.into_owned(), value.into_owned()))
		.collect::<Vec<_>>();
	let audience = match auth.resource_parameter_mode {
		McpResourceParameterMode::Resource => None,
		McpResourceParameterMode::Audience => {
			let configured = auth.audiences.first().ok_or_else(|| {
				ProxyError::ProcessingString(
					"audience resource parameter mode requires a configured audience".to_string(),
				)
			})?;
			let incoming = pairs
				.iter()
				.filter_map(|(key, value)| (key == "audience").then_some(value))
				.collect::<Vec<_>>();
			if incoming.len() > 1 || incoming.iter().any(|value| *value != configured) {
				return Ok(
					Response::builder()
						.status(StatusCode::BAD_REQUEST)
						.header(::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
						.body(Body::from(
							"authorization request audience conflicts with the configured MCP audience",
						))?,
				);
			}
			pairs.retain(|(key, _)| !matches!(key.as_str(), "resource" | "audience"));
			Some(configured.as_str())
		},
	};
	if !pairs.is_empty() || audience.is_some() {
		location
			.query_pairs_mut()
			.extend_pairs(pairs)
			.extend_pairs(audience.map(|value| ("audience", value)));
	}
	Ok(
		Response::builder()
			.status(StatusCode::FOUND)
			.header(::http::header::LOCATION, location.as_str())
			.body(axum::body::Body::empty())?,
	)
}

/// Proxy an OAuth token request, applying any provider-specific resource transformation.
/// Entra strips the RFC 8707 `resource` parameter and injects the configured client secret when the client did
/// not supply one. Entra app registrations under the Web platform are confidential clients
/// and require the secret at the token endpoint, while public clients (PKCE-only) do not.
///
/// The secret is only attached when the request is for the configured `clientId` (the app
/// registration the secret belongs to) and uses a user-delegated grant (`authorization_code`,
/// `refresh_token`). This endpoint is reachable pre-authentication, so injecting the secret
/// into other grant types — notably `client_credentials` — would let any caller mint
/// app-level tokens with the gateway's credential.
pub(super) async fn oauth_token(
	req: &mut Request,
	auth: &McpAuthentication,
	client: PolicyClient,
) -> Result<Response, ProxyError> {
	// CORS (including preflight) is the responsibility of the route's cors policy.
	if req.method() != Method::POST {
		return Ok(
			Response::builder()
				.status(StatusCode::METHOD_NOT_ALLOWED)
				.header(::http::header::ALLOW, "POST")
				.body(axum::body::Body::empty())?,
		);
	}

	let provider = McpProviderProfile::new(auth.provider.as_ref());
	let token_endpoint = provider
		.token_endpoint(auth.upstream_issuer.as_deref().unwrap_or(&auth.issuer))
		.map_err(ProxyError::ProcessingString)?
		.ok_or_else(|| ProxyError::ProcessingString("provider has no proxied token endpoint".into()))?;
	// Clients using client_secret_basic carry their credentials in the Authorization header;
	// forward it and don't inject a second credential.
	let authorization = req.headers().get(::http::header::AUTHORIZATION).cloned();
	let content_type = req.headers().get(::http::header::CONTENT_TYPE).cloned();
	let body = std::mem::take(req.body_mut());
	if !provider.strips_resource_parameter() {
		let mut builder = ::http::Request::builder()
			.uri(token_endpoint)
			.method(Method::POST);
		if let Some(content_type) = content_type {
			builder = builder.header(::http::header::CONTENT_TYPE, content_type);
		}
		if let Some(authorization) = authorization {
			builder = builder.header(::http::header::AUTHORIZATION, authorization);
		}
		return Ok(
			client
				.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
				.simple_call(builder.body(body)?)
				.await?,
		);
	}
	let limit = crate::http::buffer_limit(req);
	let bytes = crate::http::read_body_with_limit(body, limit)
		.await
		.map_err(ProxyError::Body)?;

	let parsed = match parse_entra_token_form(&bytes) {
		Ok(parsed) => parsed,
		Err(error) => {
			return Ok(
				Response::builder()
					.status(StatusCode::BAD_REQUEST)
					.header(::http::header::CONTENT_TYPE, "application/json")
					.body(Body::from(
						serde_json::json!({"error": "invalid_request", "error_description": error}).to_string(),
					))?,
			);
		},
	};
	// The configured secret belongs to the app registration identified by the configured
	// clientId (the one the DCR short-circuit hands out); never attach it to a request for
	// any other client_id.
	let client_id_matches = auth.client_id.is_some() && parsed.client_id == auth.client_id;
	let mut form = parsed.form;
	if authorization.is_none()
		&& !parsed.has_client_secret
		&& client_id_matches
		&& provider.may_inject_client_secret(parsed.grant_type.as_deref())
		&& let Some(secret) = &auth.client_secret
	{
		form = url::form_urlencoded::Serializer::new(form)
			.append_pair("client_secret", secret.expose_secret())
			.finish();
	}

	let mut builder = ::http::Request::builder()
		.uri(token_endpoint)
		.method(Method::POST)
		.header(
			::http::header::CONTENT_TYPE,
			"application/x-www-form-urlencoded",
		);
	if let Some(authorization) = authorization {
		builder = builder.header(::http::header::AUTHORIZATION, authorization);
	}
	let ureq = builder.body(Body::from(form))?;
	let upstream = client
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Oidc)
		.simple_call(ureq)
		.await?;

	Ok(upstream)
}

/// An OAuth token request form re-encoded without any `resource` parameters, plus the fields
/// needed to decide whether the configured client secret may be attached.
struct EntraTokenForm {
	form: String,
	has_client_secret: bool,
	grant_type: Option<String>,
	client_id: Option<String>,
}

fn parse_entra_token_form(input: &[u8]) -> Result<EntraTokenForm, String> {
	let mut has_client_secret = false;
	let mut grant_type = None;
	let mut client_id = None;
	let mut serializer = url::form_urlencoded::Serializer::new(String::new());
	for (k, v) in url::form_urlencoded::parse(input) {
		match k.as_ref() {
			"client_secret" if has_client_secret => {
				return Err("duplicate client_secret parameter".to_string());
			},
			"client_secret" => has_client_secret = true,
			"grant_type" if grant_type.is_some() => {
				return Err("duplicate grant_type parameter".to_string());
			},
			"grant_type" => grant_type = Some(v.to_string()),
			"client_id" if client_id.is_some() => {
				return Err("duplicate client_id parameter".to_string());
			},
			"client_id" => client_id = Some(v.to_string()),
			_ => {},
		}
		if k != "resource" {
			serializer.append_pair(&k, &v);
		}
	}
	Ok(EntraTokenForm {
		form: serializer.finish(),
		has_client_secret,
		grant_type,
		client_id,
	})
}

const MOCK_DCR_CLIENT_ID_ISSUED_AT: u64 = 0;

/// Build the mock Dynamic Client Registration response used when
/// `MCPAuthentication.clientId` is configured.
///
/// This path is for pre-registered IdP clients. The gateway is not creating
/// a client upstream, so return deterministic registration metadata and carry
/// forward only the requested redirect URIs that strict MCP clients validate.
async fn build_mock_dcr_response(
	req: &mut Request,
	client_id: &str,
) -> Result<Response, ProxyError> {
	let limit = crate::http::buffer_limit(req);
	let body = std::mem::take(req.body_mut());
	let bytes = crate::http::read_body_with_limit(body, limit)
		.await
		.map_err(ProxyError::Body)?;

	let redirect_uris = serde_json::from_slice::<serde_json::Value>(&bytes)
		.ok()
		.and_then(|json| json.get("redirect_uris").filter(|v| v.is_array()).cloned())
		.unwrap_or_else(|| serde_json::json!([]));

	let response_json = serde_json::json!({
		"client_id": client_id,
		"client_id_issued_at": MOCK_DCR_CLIENT_ID_ISSUED_AT,
		"token_endpoint_auth_method": "none",
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"redirect_uris": redirect_uris,
	});

	let body_bytes = bytes::Bytes::from(
		serde_json::to_vec(&response_json).map_err(|e| ProxyError::ProcessingString(e.to_string()))?,
	);
	Ok(
		Response::builder()
			.status(::http::StatusCode::CREATED)
			.header(::http::header::CONTENT_TYPE, "application/json")
			.body(body_bytes.into())?,
	)
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::http::jwt::{Claims, CredentialConsumed};

	#[test]
	fn www_authenticate_resource_metadata_preserves_authority_for_root_path() {
		let req = auth_request("https://example.com/", default_auth());

		assert_eq!(
			www_authenticate_resource_metadata(&req),
			"Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/\""
		);
	}

	#[test]
	fn www_authenticate_resource_metadata_preserves_authority_when_path_matches_host_prefix() {
		let req = auth_request("https://example.com/example.com", default_auth());

		assert_eq!(
			www_authenticate_resource_metadata(&req),
			"Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/example.com\""
		);
	}

	#[test]
	fn www_authenticate_resource_metadata_preserves_authority_for_non_matching_path() {
		let req = auth_request("https://example.com/sse", default_auth());

		assert_eq!(
			www_authenticate_resource_metadata(&req),
			"Bearer resource_metadata=\"https://example.com/.well-known/oauth-protected-resource/sse\""
		);
	}

	#[test]
	fn auth_required_response_uses_configured_resource_with_path() {
		let req = auth_request(
			"http://backend.internal/mcp",
			McpAuthentication {
				issuer: "https://idp.example.com".to_string(),
				upstream_issuer: None,
				audiences: Vec::new(),
				resource_parameter_mode: McpResourceParameterMode::Resource,
				provider: None,
				resource_metadata: crate::types::agent::ResourceMetadata {
					extra: std::collections::BTreeMap::from([(
						"resource".to_string(),
						serde_json::Value::String("https://gateway.example.com/base/path".to_string()),
					)]),
				},
				jwt_validator: Arc::new(crate::http::jwt::Jwt::from_providers(
					Vec::new(),
					crate::http::jwt::Mode::Strict,
					crate::http::auth::AuthorizationLocation::default(),
					false,
				)),
				mode: crate::types::agent::McpAuthenticationMode::Strict,
				client_id: None,
				client_secret: None,
			},
		);

		assert_eq!(
			www_authenticate_resource_metadata(&req),
			"Bearer resource_metadata=\"https://gateway.example.com/.well-known/oauth-protected-resource/base/path\""
		);
	}

	fn auth_request(uri: &'static str, auth: McpAuthentication) -> Request {
		let mut req = ::http::Request::builder()
			.uri(uri)
			.body(Body::empty())
			.expect("request should build");
		req.extensions_mut().insert(auth);
		req
	}

	fn default_auth() -> McpAuthentication {
		McpAuthentication {
			issuer: "https://issuer.example.com".to_string(),
			upstream_issuer: None,
			audiences: vec!["mcp".to_string()],
			resource_parameter_mode: McpResourceParameterMode::Resource,
			provider: None,
			resource_metadata: crate::types::agent::ResourceMetadata {
				extra: Default::default(),
			},
			jwt_validator: Arc::new(crate::http::jwt::Jwt::from_providers(
				vec![],
				crate::http::jwt::Mode::Strict,
				crate::http::auth::AuthorizationLocation::bearer_header(),
				false,
			)),
			mode: crate::types::agent::McpAuthenticationMode::Strict,
			client_id: None,
			client_secret: None,
		}
	}

	fn validator(mode: crate::http::jwt::Mode) -> Jwt {
		Jwt::from_providers(
			vec![],
			mode,
			crate::http::auth::AuthorizationLocation::bearer_header(),
			false,
		)
	}

	fn prior_claims(subject: &str) -> Claims {
		Claims {
			inner: serde_json::Map::from_iter([(
				"sub".to_string(),
				serde_json::Value::String(subject.to_string()),
			)]),
			jwt: secrecy::SecretString::new("earlier-token".into()),
		}
	}

	#[tokio::test]
	async fn stripped_earlier_credentials_are_rejected_in_every_mode() {
		for mode in [
			crate::http::jwt::Mode::Strict,
			crate::http::jwt::Mode::Optional,
			crate::http::jwt::Mode::Permissive,
		] {
			let mut req = ::http::Request::builder()
				.uri("https://gateway.example/mcp")
				.body(Body::empty())
				.expect("request should build");
			req.extensions_mut().insert(prior_claims("earlier"));
			req.extensions_mut().insert(CredentialConsumed::at(
				crate::http::auth::AuthorizationLocation::bearer_header(),
			));

			let result = apply_token_validation(&mut req, &default_auth(), &validator(mode), None).await;

			assert!(matches!(
				result,
				Err(ProxyError::McpJwtAuthenticationFailure(_, _))
			));
			assert_eq!(
				req
					.extensions()
					.get::<Claims>()
					.and_then(|claims| claims.inner.get("sub")),
				Some(&serde_json::Value::String("earlier".to_string()))
			);
		}
	}

	#[tokio::test]
	async fn consumed_non_bearer_credentials_do_not_block_optional_mcp_authentication() {
		for mode in [
			crate::http::jwt::Mode::Optional,
			crate::http::jwt::Mode::Permissive,
		] {
			let mut req = ::http::Request::builder()
				.uri("https://gateway.example/mcp")
				.body(Body::empty())
				.expect("request should build");
			req.extensions_mut().insert(prior_claims("earlier"));
			req.extensions_mut().insert(CredentialConsumed::at(
				crate::http::auth::AuthorizationLocation::Cookie {
					name: "session".into(),
				},
			));

			apply_token_validation(&mut req, &default_auth(), &validator(mode), None)
				.await
				.expect("an unrelated consumed credential must not require a bearer token");
		}
	}

	/// An OIDC policy leaves session claims behind without ever touching the bearer header, so
	/// those claims must not be mistaken for a token an earlier JWT policy stripped.
	#[tokio::test]
	async fn session_claims_without_a_consumed_credential_follow_the_configured_mode() {
		for (mode, rejected) in [
			(crate::http::jwt::Mode::Strict, true),
			(crate::http::jwt::Mode::Optional, false),
			(crate::http::jwt::Mode::Permissive, false),
		] {
			let mut req = ::http::Request::builder()
				.uri("https://gateway.example/mcp")
				.body(Body::empty())
				.expect("request should build");
			req.extensions_mut().insert(prior_claims("session-user"));

			let result = apply_token_validation(&mut req, &default_auth(), &validator(mode), None).await;

			assert_eq!(result.is_err(), rejected, "mode={mode:?}");
			assert_eq!(
				req
					.extensions()
					.get::<Claims>()
					.and_then(|claims| claims.inner.get("sub")),
				Some(&serde_json::Value::String("session-user".to_string())),
				"mode={mode:?}"
			);
		}
	}

	#[tokio::test]
	async fn permissive_revalidation_preserves_earlier_identity() {
		let mut req = ::http::Request::builder()
			.uri("https://gateway.example/mcp")
			.header(::http::header::AUTHORIZATION, "Bearer invalid-token")
			.body(Body::empty())
			.expect("request should build");
		req.extensions_mut().insert(prior_claims("earlier"));

		apply_token_validation(
			&mut req,
			&default_auth(),
			&validator(crate::http::jwt::Mode::Permissive),
			None,
		)
		.await
		.expect("permissive validation should allow an invalid retained token");

		assert_eq!(
			req
				.extensions()
				.get::<Claims>()
				.and_then(|claims| claims.inner.get("sub")),
			Some(&serde_json::Value::String("earlier".to_string()))
		);
		assert!(req.headers().contains_key(::http::header::AUTHORIZATION));
	}

	#[tokio::test]
	async fn optional_revalidation_rejects_an_invalid_retained_token() {
		let mut req = ::http::Request::builder()
			.uri("https://gateway.example/mcp")
			.header(::http::header::AUTHORIZATION, "Bearer invalid-token")
			.body(Body::empty())
			.expect("request should build");
		req.extensions_mut().insert(prior_claims("earlier"));

		let result = apply_token_validation(
			&mut req,
			&default_auth(),
			&validator(crate::http::jwt::Mode::Optional),
			None,
		)
		.await;

		assert!(matches!(
			result,
			Err(ProxyError::McpJwtAuthenticationFailure(_, _))
		));
		assert_eq!(
			req
				.extensions()
				.get::<Claims>()
				.and_then(|claims| claims.inner.get("sub")),
			Some(&serde_json::Value::String("earlier".to_string()))
		);
	}

	#[tokio::test]
	async fn revalidation_extracts_expression_credential_before_clearing_claims() {
		let validator = Jwt::from_providers(
			vec![],
			crate::http::jwt::Mode::Strict,
			crate::http::auth::AuthorizationLocation::Expression(Arc::new(
				crate::cel::Expression::new_strict("jwt.rawToken.unredacted()")
					.expect("expression should compile"),
			)),
			false,
		);
		let mut req = ::http::Request::builder()
			.uri("https://gateway.example/mcp")
			.body(Body::empty())
			.expect("request should build");
		req.extensions_mut().insert(prior_claims("earlier"));

		let result = apply_token_validation(&mut req, &default_auth(), &validator, None).await;

		assert!(matches!(
			result,
			Err(ProxyError::McpJwtAuthenticationFailure(inner, _))
				if matches!(*inner, ProxyError::JwtAuthenticationFailure(crate::http::jwt::TokenError::InvalidHeader(_)))
		));
		assert_eq!(
			req
				.extensions()
				.get::<Claims>()
				.and_then(|claims| claims.inner.get("sub")),
			Some(&serde_json::Value::String("earlier".to_string()))
		);
	}

	fn www_authenticate_resource_metadata(req: &Request) -> String {
		let err = create_auth_required_response(
			ProxyError::ProcessingString("test auth failure".to_string()),
			req,
			req
				.extensions()
				.get::<McpAuthentication>()
				.expect("auth should be set"),
		);

		match err {
			ProxyError::McpJwtAuthenticationFailure(_, www_authenticate) => www_authenticate,
			other => panic!("expected MCP JWT authentication failure, got {other:?}"),
		}
	}

	async fn response_body_to_json(resp: Response) -> serde_json::Value {
		let bytes = crate::http::read_resp_body(resp)
			.await
			.expect("response body should read");
		serde_json::from_slice(&bytes).expect("response body should be JSON")
	}

	fn dcr_request(body: &'static str) -> Request {
		::http::Request::builder()
			.method(Method::POST)
			.uri("https://gateway.example.com/client-registration")
			.header(::http::header::CONTENT_TYPE, "application/json")
			.body(Body::from(body))
			.expect("request should build")
	}

	#[tokio::test]
	async fn mock_dcr_echoes_redirect_uris_and_overrides_client_id() {
		let body = r#"{"redirect_uris":["http://localhost:33418/callback"],"grant_types":["authorization_code"],"client_name":"Claude Code"}"#;
		let mut req = dcr_request(body);

		let resp = build_mock_dcr_response(&mut req, "0oa1wcsu7sbWwq3Ht358")
			.await
			.expect("mock should build");

		assert_eq!(resp.status(), ::http::StatusCode::CREATED);
		let json = response_body_to_json(resp).await;
		assert_eq!(json["client_id"], "0oa1wcsu7sbWwq3Ht358");
		assert_eq!(
			json["redirect_uris"],
			serde_json::json!(["http://localhost:33418/callback"])
		);
		assert_eq!(
			json["grant_types"],
			serde_json::json!(["authorization_code"])
		);
		assert_eq!(json["response_types"], serde_json::json!(["code"]));
		assert_eq!(json["token_endpoint_auth_method"], "none");
		assert_eq!(json["client_id_issued_at"], MOCK_DCR_CLIENT_ID_ISSUED_AT);
		assert!(json.get("client_name").is_none());
	}

	#[tokio::test]
	async fn mock_dcr_overrides_client_id_if_client_submitted_one() {
		// If a client submitted its own client_id (unusual but possible),
		// we override it with the operator-configured value rather than
		// honoring what the client sent.
		let body = r#"{"redirect_uris":["http://localhost:1234/cb"],"client_id":"client-supplied-id"}"#;
		let mut req = dcr_request(body);

		let resp = build_mock_dcr_response(&mut req, "operator-id")
			.await
			.expect("mock should build");

		let json = response_body_to_json(resp).await;
		assert_eq!(json["client_id"], "operator-id");
		assert_eq!(
			json["redirect_uris"],
			serde_json::json!(["http://localhost:1234/cb"])
		);
	}

	#[tokio::test]
	async fn mock_dcr_handles_empty_body() {
		let mut req = ::http::Request::builder()
			.method(Method::POST)
			.uri("https://gateway.example.com/client-registration")
			.body(Body::empty())
			.expect("request should build");

		let resp = build_mock_dcr_response(&mut req, "operator-id")
			.await
			.expect("mock should build for empty body");

		let json = response_body_to_json(resp).await;
		assert_eq!(json["client_id"], "operator-id");
		assert_eq!(json["client_id_issued_at"], MOCK_DCR_CLIENT_ID_ISSUED_AT);
		assert_eq!(json["redirect_uris"], serde_json::json!([]));
	}

	#[tokio::test]
	async fn mock_dcr_handles_malformed_json() {
		let mut req = dcr_request("this is not json {{{");

		let resp = build_mock_dcr_response(&mut req, "operator-id")
			.await
			.expect("mock should build for invalid JSON");

		let json = response_body_to_json(resp).await;
		assert_eq!(json["client_id"], "operator-id");
		assert_eq!(json["redirect_uris"], serde_json::json!([]));
	}

	#[tokio::test]
	async fn mock_dcr_handles_non_object_body() {
		let mut req = dcr_request(r#"["not", "an", "object"]"#);

		let resp = build_mock_dcr_response(&mut req, "operator-id")
			.await
			.expect("mock should build for non-object body");

		let json = response_body_to_json(resp).await;
		assert_eq!(json["client_id"], "operator-id");
		assert!(json.is_object());
		assert_eq!(json["redirect_uris"], serde_json::json!([]));
	}

	#[tokio::test]
	async fn configured_client_registration_short_circuits_every_provider() {
		for provider in [
			None,
			Some(McpIDP::Auth0 {}),
			Some(McpIDP::Keycloak {}),
			Some(McpIDP::Okta {}),
			Some(McpIDP::Descope {}),
			Some(McpIDP::Authentik {}),
			Some(McpIDP::Entra {}),
		] {
			let mut auth = default_auth();
			auth.provider = provider;
			auth.client_id = Some("configured-client".to_string());
			let mut req = dcr_request(r#"{"redirect_uris":["http://localhost/callback"]}"#);

			let response = client_registration(&mut req, &auth, crate::test_helpers::policy_client())
				.await
				.expect("configured registration should not call the provider");

			assert_eq!(response.status(), StatusCode::CREATED);
			assert_eq!(
				response_body_to_json(response).await["client_id"],
				"configured-client"
			);
		}
	}

	fn entra_auth() -> McpAuthentication {
		McpAuthentication {
			issuer: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
				.to_string(),
			upstream_issuer: None,
			audiences: vec!["api://client-id-guid".to_string()],
			resource_parameter_mode: McpResourceParameterMode::Resource,
			provider: Some(McpIDP::Entra {}),
			resource_metadata: crate::types::agent::ResourceMetadata {
				extra: Default::default(),
			},
			jwt_validator: Arc::new(crate::http::jwt::Jwt::from_providers(
				vec![],
				crate::http::jwt::Mode::Strict,
				crate::http::auth::AuthorizationLocation::bearer_header(),
				false,
			)),
			mode: crate::types::agent::McpAuthenticationMode::Strict,
			client_id: Some("client-id-guid".to_string()),
			client_secret: None,
		}
	}

	fn okta_auth(
		audiences: Vec<String>,
		resource_parameter_mode: McpResourceParameterMode,
	) -> McpAuthentication {
		McpAuthentication {
			issuer: "https://tenant.okta.com/oauth2/default".to_string(),
			upstream_issuer: None,
			audiences,
			resource_parameter_mode,
			provider: Some(McpIDP::Okta {}),
			..entra_auth()
		}
	}

	#[test]
	fn okta_authorize_preserves_native_resource_and_pkce() {
		let req = ::http::Request::builder()
			.uri("https://gateway.example.com/mcp/authorize?client_id=abc&resource=https%3A%2F%2Fgateway.example.com%2Fmcp&resource=https%3A%2F%2Fgateway.example.com%2Fsecond&code_challenge=ccc&code_challenge_method=S256")
			.body(Body::empty())
			.expect("request should build");

		let resp = oauth_authorize(
			&req,
			&okta_auth(
				vec!["legacy-api".to_string()],
				McpResourceParameterMode::Resource,
			),
		)
		.expect("authorize should redirect");
		let location = resp.headers()[::http::header::LOCATION]
			.to_str()
			.expect("location should be a string");

		assert!(location.starts_with("https://tenant.okta.com/oauth2/default/v1/authorize?"));
		assert_eq!(location.matches("resource=").count(), 2);
		assert!(location.contains("code_challenge=ccc"));
		assert!(!location.contains("audience="));
	}

	#[test]
	fn okta_authorize_audience_mode_replaces_resource() {
		let req = ::http::Request::builder()
			.uri("https://gateway.example.com/mcp/authorize?client_id=abc&resource=https%3A%2F%2Fgateway.example.com%2Fmcp&state=state")
			.body(Body::empty())
			.expect("request should build");

		let resp = oauth_authorize(
			&req,
			&okta_auth(
				vec!["api://mcp".to_string()],
				McpResourceParameterMode::Audience,
			),
		)
		.expect("authorize should redirect");
		let location = resp.headers()[::http::header::LOCATION]
			.to_str()
			.expect("location should be a string");
		assert!(location.contains("audience=api%3A%2F%2Fmcp"));
		assert!(!location.contains("resource="));
	}

	#[test]
	fn okta_authorize_rejects_conflicting_audience() {
		let req = ::http::Request::builder()
			.uri("https://gateway.example.com/mcp/authorize?client_id=abc&audience=other")
			.body(Body::empty())
			.expect("request should build");
		let resp = oauth_authorize(
			&req,
			&okta_auth(
				vec!["api://mcp".to_string()],
				McpResourceParameterMode::Audience,
			),
		)
		.expect("conflict should produce a response");
		assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
	}

	#[test]
	fn entra_authorize_strips_resource_param() {
		// Entra rejects RFC 8707 `resource` with AADSTS9010010; everything else must be preserved.
		let req = ::http::Request::builder()
			.uri("https://gateway.example.com/.well-known/oauth-authorization-server/mcp/authorize?client_id=abc&resource=https%3A%2F%2Fgateway.example.com%2Fmcp&state=xyz&code_challenge=ccc&code_challenge_method=S256")
			.body(Body::empty())
			.expect("request should build");

		let resp = oauth_authorize(&req, &entra_auth()).expect("authorize should redirect");

		assert_eq!(resp.status(), StatusCode::FOUND);
		let location = resp
			.headers()
			.get(::http::header::LOCATION)
			.expect("location header")
			.to_str()
			.expect("location should be a string");
		assert!(
			location.starts_with(
				"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?"
			),
			"unexpected location: {location}"
		);
		assert!(
			!location.contains("resource="),
			"unexpected location: {location}"
		);
		assert!(
			location.contains("client_id=abc"),
			"unexpected location: {location}"
		);
		assert!(
			location.contains("state=xyz"),
			"unexpected location: {location}"
		);
		assert!(
			location.contains("code_challenge_method=S256"),
			"unexpected location: {location}"
		);
	}

	#[test]
	fn entra_authorize_without_query_redirects_to_bare_endpoint() {
		let req = ::http::Request::builder()
			.uri("https://gateway.example.com/.well-known/oauth-authorization-server/mcp/authorize")
			.body(Body::empty())
			.expect("request should build");

		let resp = oauth_authorize(&req, &entra_auth()).expect("authorize should redirect");

		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(
			resp
				.headers()
				.get(::http::header::LOCATION)
				.expect("location header"),
			"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize"
		);
	}

	#[tokio::test]
	async fn entra_token_rejects_non_post_methods() {
		let client = crate::test_helpers::policy_client();
		let mut req = ::http::Request::builder()
			.method(Method::GET)
			.uri("https://gateway.example.com/.well-known/oauth-authorization-server/mcp/token")
			.body(Body::empty())
			.expect("request should build");

		let resp = oauth_token(&mut req, &entra_auth(), client)
			.await
			.expect("non-POST should get a response");

		assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
		assert_eq!(
			resp.headers().get(::http::header::ALLOW).expect("allow"),
			"POST"
		);
	}

	#[test]
	fn parse_entra_token_form_removes_resource_and_detects_client_secret() {
		let parsed = parse_entra_token_form(
			b"grant_type=authorization_code&client_id=abc-123&code=abc&resource=https%3A%2F%2Fgw%2Fmcp&code_verifier=v",
		)
		.expect("form should parse");
		assert!(!parsed.has_client_secret);
		assert_eq!(parsed.grant_type.as_deref(), Some("authorization_code"));
		assert_eq!(parsed.client_id.as_deref(), Some("abc-123"));
		assert!(!parsed.form.contains("resource"));
		assert!(parsed.form.contains("grant_type=authorization_code"));
		assert!(parsed.form.contains("code=abc"));
		assert!(parsed.form.contains("code_verifier=v"));

		let parsed = parse_entra_token_form(b"grant_type=refresh_token&client_secret=s3cret")
			.expect("form should parse");
		assert!(parsed.has_client_secret);
		assert_eq!(parsed.grant_type.as_deref(), Some("refresh_token"));
		assert!(parsed.form.contains("client_secret=s3cret"));
	}

	#[test]
	fn parse_entra_token_form_rejects_ambiguous_credential_fields() {
		for form in [
			b"client_id=a&client_id=b".as_slice(),
			b"grant_type=authorization_code&grant_type=refresh_token".as_slice(),
			b"client_secret=a&client_secret=b".as_slice(),
		] {
			assert!(parse_entra_token_form(form).is_err());
		}
	}

	#[test]
	fn entra_client_secret_only_attaches_to_user_delegated_grants() {
		let provider = McpProviderProfile::new(Some(&McpIDP::Entra {}));
		assert!(provider.may_inject_client_secret(Some("authorization_code")));
		assert!(provider.may_inject_client_secret(Some("refresh_token")));
		// A hostile page could POST these pre-auth; the gateway must never attach its secret.
		assert!(!provider.may_inject_client_secret(Some("client_credentials")));
		assert!(
			!provider.may_inject_client_secret(Some("urn:ietf:params:oauth:grant-type:jwt-bearer"))
		);
		assert!(!provider.may_inject_client_secret(None));
	}
}
