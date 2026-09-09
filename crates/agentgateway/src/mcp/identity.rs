use std::fmt;

use http::Method;

use crate::http::{Request, filters};
use crate::types::agent::{McpAuthentication, McpIDP};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum McpEndpoint {
	ProtectedResourceMetadata,
	AuthorizationServerMetadata,
	Authorization,
	Token,
	Registration,
}

impl McpEndpoint {
	pub(crate) fn allowed_methods(self) -> &'static str {
		match self {
			Self::ProtectedResourceMetadata | Self::AuthorizationServerMetadata | Self::Authorization => {
				"GET, OPTIONS"
			},
			Self::Token | Self::Registration => "POST, OPTIONS",
		}
	}

	pub(crate) fn accepts(self, method: &Method) -> bool {
		method == Method::OPTIONS
			|| match self {
				Self::ProtectedResourceMetadata
				| Self::AuthorizationServerMetadata
				| Self::Authorization => method == Method::GET,
				Self::Token | Self::Registration => method == Method::POST,
			}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct IdentityUri {
	parsed: url::Url,
	value: String,
	origin: String,
	path: String,
}

impl IdentityUri {
	fn from_configured(value: &str, field: &str) -> Result<Self, String> {
		let parsed = validate_url(value, field)?;
		let authority_start = value
			.find("://")
			.map(|index| index + 3)
			.ok_or_else(|| format!("invalid {field}: missing authority"))?;
		let path_start = value[authority_start..]
			.find('/')
			.map(|index| authority_start + index);
		let path = path_start
			.map(|index| value[index..].to_string())
			.unwrap_or_default();
		Ok(Self {
			parsed,
			value: value.to_string(),
			origin: path_start
				.map(|index| value[..index].to_string())
				.unwrap_or_else(|| value.to_string()),
			path,
		})
	}

	fn from_url(parsed: url::Url) -> Self {
		Self {
			path: parsed.path().to_string(),
			value: parsed.to_string(),
			origin: parsed.origin().ascii_serialization(),
			parsed,
		}
	}

	pub(crate) fn as_str(&self) -> &str {
		&self.value
	}

	pub(crate) fn path(&self) -> &str {
		&self.path
	}
}

impl fmt::Display for IdentityUri {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(&self.value)
	}
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedMcpIdentity {
	pub(crate) public_resource: IdentityUri,
	pub(crate) public_authorization_server: IdentityUri,
	pub(crate) upstream_discovery_issuer: IdentityUri,
	pub(crate) expected_token_issuer: String,
	resource_was_configured: bool,
}

impl ResolvedMcpIdentity {
	pub(crate) fn resolve(req: &Request, auth: &McpAuthentication) -> Result<Self, String> {
		let external = external_request_url(req)?;
		let upstream_discovery_issuer = validate_identity_uri(
			auth.upstream_issuer.as_deref().unwrap_or(&auth.issuer),
			"upstreamIssuer",
		)?;
		validate_identity_uri(&auth.issuer, "issuer")?;

		let configured_resource = auth.resource_metadata.resource_uri()?;
		let resource_was_configured = configured_resource.is_some();
		let public_resource = match configured_resource {
			Some(resource) => validate_identity_uri(&resource, "resourceMetadata.resource")?,
			None => infer_public_resource(&external, auth.provider.as_ref()),
		};
		let public_authorization_server = match auth.resource_metadata.authorization_server_uri()? {
			Some(issuer) => validate_identity_uri(&issuer, "resourceMetadata.authorizationServers")?,
			None if auth.provider.is_some() => public_resource.clone(),
			None => upstream_discovery_issuer.clone(),
		};

		Ok(Self {
			public_resource,
			public_authorization_server,
			upstream_discovery_issuer,
			expected_token_issuer: auth.issuer.clone(),
			resource_was_configured,
		})
	}

	pub(crate) fn endpoint(&self, req: &Request, provider: Option<&McpIDP>) -> Option<McpEndpoint> {
		if !self.resource_was_configured
			&& !req
				.extensions()
				.get::<crate::types::agent::PathMatch>()
				.is_some_and(|matched| matches!(matched, crate::types::agent::PathMatch::Exact(_)))
		{
			return None;
		}
		let external = external_request_url(req).ok()?;
		let path = external.path();
		if same_origin(&external, &self.public_resource)
			&& path
				== inserted_well_known(
					"/.well-known/oauth-protected-resource",
					self.public_resource.path(),
				) {
			return Some(McpEndpoint::ProtectedResourceMetadata);
		}
		if provider.is_none() {
			let compatibility_path = inserted_well_known(
				"/.well-known/oauth-authorization-server",
				self.public_resource.path(),
			);
			return (same_origin(&external, &self.public_resource)
				&& self.explicit_alias(req, &compatibility_path))
			.then_some(McpEndpoint::AuthorizationServerMetadata);
		}
		if !same_origin(&external, &self.public_authorization_server) {
			return None;
		}

		let issuer_path = self.public_authorization_server.path();
		if path == inserted_well_known("/.well-known/oauth-authorization-server", issuer_path)
			|| self.explicit_alias(
				req,
				&appended(issuer_path, "/.well-known/oauth-authorization-server"),
			) || self.explicit_alias(
			req,
			&appended(issuer_path, "/.well-known/openid-configuration"),
		) {
			return Some(McpEndpoint::AuthorizationServerMetadata);
		}

		let mut operations = vec![("client-registration", McpEndpoint::Registration)];
		if matches!(provider, Some(McpIDP::Entra {})) {
			operations.extend([
				("authorize", McpEndpoint::Authorization),
				("token", McpEndpoint::Token),
			]);
		}
		for (suffix, endpoint) in operations {
			if path == appended(issuer_path, &format!("/{suffix}")) {
				return Some(endpoint);
			}
			let legacy = appended(
				&inserted_well_known("/.well-known/oauth-authorization-server", issuer_path),
				&format!("/{suffix}"),
			);
			if self.explicit_alias(req, &legacy) {
				return Some(endpoint);
			}
		}
		None
	}

	fn explicit_alias(&self, req: &Request, alias: &str) -> bool {
		external_request_url(req).is_ok_and(|url| url.path() == alias)
			&& req
				.extensions()
				.get::<crate::types::agent::PathMatch>()
				.is_some_and(
					|matched| matches!(matched, crate::types::agent::PathMatch::Exact(path) if &**path == alias),
				)
	}

	pub(crate) fn protected_resource_metadata_url(&self) -> String {
		url_with_path(
			&self.public_resource,
			&inserted_well_known(
				"/.well-known/oauth-protected-resource",
				self.public_resource.path(),
			),
		)
	}

	pub(crate) fn authorization_server_metadata_url(&self) -> String {
		url_with_path(
			&self.public_authorization_server,
			&inserted_well_known(
				"/.well-known/oauth-authorization-server",
				self.public_authorization_server.path(),
			),
		)
	}

	pub(crate) fn authorization_url(&self) -> String {
		url_with_path(
			&self.public_authorization_server,
			&appended(self.public_authorization_server.path(), "/authorize"),
		)
	}

	pub(crate) fn token_url(&self) -> String {
		url_with_path(
			&self.public_authorization_server,
			&appended(self.public_authorization_server.path(), "/token"),
		)
	}

	pub(crate) fn registration_url(&self) -> String {
		url_with_path(
			&self.public_authorization_server,
			&appended(
				self.public_authorization_server.path(),
				"/client-registration",
			),
		)
	}
}

pub(crate) fn validate_configured_identity(auth: &McpAuthentication) -> Result<(), String> {
	validate_identity_uri(&auth.issuer, "issuer")?;
	validate_identity_uri(
		auth.upstream_issuer.as_deref().unwrap_or(&auth.issuer),
		"upstreamIssuer",
	)?;
	if let Some(resource) = auth.resource_metadata.resource_uri()? {
		validate_identity_uri(&resource, "resourceMetadata.resource")?;
	}
	if let Some(issuer) = auth.resource_metadata.authorization_server_uri()? {
		validate_identity_uri(&issuer, "resourceMetadata.authorizationServers")?;
	}
	Ok(())
}

pub(crate) fn is_discovery_candidate(path: &str) -> bool {
	path == "/.well-known/oauth-protected-resource"
		|| path.starts_with("/.well-known/oauth-protected-resource/")
		|| path == "/.well-known/oauth-authorization-server"
		|| path.starts_with("/.well-known/oauth-authorization-server/")
		|| path.ends_with("/.well-known/oauth-authorization-server")
		|| path.ends_with("/.well-known/openid-configuration")
}

fn validate_identity_uri(value: &str, field: &str) -> Result<IdentityUri, String> {
	IdentityUri::from_configured(value, field)
}

fn validate_url(value: &str, field: &str) -> Result<url::Url, String> {
	let parsed = url::Url::parse(value).map_err(|error| format!("invalid {field}: {error}"))?;
	if !matches!(parsed.scheme(), "http" | "https") {
		return Err(format!("{field} must use http or https"));
	}
	let loopback = match parsed.host() {
		Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
		Some(url::Host::Ipv4(host)) => host.is_loopback(),
		Some(url::Host::Ipv6(host)) => host.is_loopback(),
		None => false,
	};
	if parsed.scheme() == "http" && !loopback {
		return Err(format!(
			"{field} must use https unless its host is loopback"
		));
	}
	if !parsed.username().is_empty() || parsed.password().is_some() {
		return Err(format!("{field} must not contain userinfo"));
	}
	if parsed.query().is_some() || parsed.fragment().is_some() {
		return Err(format!("{field} must not contain a query or fragment"));
	}
	if value.split('/').any(|segment| {
		let segment = segment.to_ascii_lowercase();
		matches!(
			segment.as_str(),
			"." | ".." | "%2e" | "%2e%2e" | ".%2e" | "%2e."
		)
	}) {
		return Err(format!("{field} must not contain dot segments"));
	}
	Ok(parsed)
}

fn external_request_url(req: &Request) -> Result<url::Url, String> {
	let uri = req
		.extensions()
		.get::<filters::OriginalUrl>()
		.map(|url| url.0.clone())
		.unwrap_or_else(|| req.uri().clone());
	let uri = crate::http::x_headers::apply_forwarded_scheme(uri, req.headers());
	url::Url::parse(&uri.to_string())
		.map_err(|error| format!("invalid external request URL: {error}"))
}

fn infer_public_resource(external: &url::Url, provider: Option<&McpIDP>) -> IdentityUri {
	let path = external.path();
	let discovered_path = path
		.strip_prefix("/.well-known/oauth-protected-resource")
		.or_else(|| provider.and_then(|_| path.strip_prefix("/.well-known/oauth-authorization-server")))
		.unwrap_or(path);
	let resource_path = provider
		.and_then(|_| {
			["/authorize", "/token", "/client-registration"]
				.into_iter()
				.find_map(|suffix| discovered_path.strip_suffix(suffix))
		})
		.unwrap_or(discovered_path);
	let mut resource = external.clone();
	resource.set_path(if resource_path.is_empty() {
		"/"
	} else {
		resource_path
	});
	resource.set_query(None);
	resource.set_fragment(None);
	IdentityUri::from_url(resource)
}

fn same_origin(left: &url::Url, right: &IdentityUri) -> bool {
	left.scheme() == right.parsed.scheme()
		&& left.host() == right.parsed.host()
		&& left.port_or_known_default() == right.parsed.port_or_known_default()
}

fn inserted_well_known(prefix: &str, path: &str) -> String {
	if path == "/" {
		format!("{prefix}/")
	} else {
		format!("{prefix}{path}")
	}
}

fn appended(path: &str, suffix: &str) -> String {
	format!("{}{}", path.trim_end_matches('/'), suffix)
}

fn url_with_path(base: &IdentityUri, path: &str) -> String {
	format!("{}{path}", base.origin)
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::types::agent::{McpAuthenticationMode, ResourceMetadata};

	fn auth(resource: Option<&str>, provider: Option<McpIDP>) -> McpAuthentication {
		McpAuthentication {
			issuer: "https://tokens.example/tenant".to_string(),
			upstream_issuer: Some("https://discovery.example/tenant".to_string()),
			audiences: vec!["mcp".to_string()],
			provider,
			resource_metadata: ResourceMetadata {
				extra: resource
					.map(|resource| {
						std::collections::BTreeMap::from([(
							"resource".to_string(),
							serde_json::Value::String(resource.to_string()),
						)])
					})
					.unwrap_or_default(),
			},
			jwt_validator: Arc::new(crate::http::jwt::Jwt::from_providers(
				vec![],
				crate::http::jwt::Mode::Strict,
				crate::http::auth::AuthorizationLocation::bearer_header(),
				false,
			)),
			mode: McpAuthenticationMode::Strict,
			client_id: None,
			client_secret: None,
		}
	}

	fn request(uri: &str, matched: crate::types::agent::PathMatch) -> Request {
		let mut request = ::http::Request::builder()
			.uri(uri)
			.body(crate::http::Body::empty())
			.expect("request");
		request.extensions_mut().insert(matched);
		request
	}

	#[test]
	fn inserted_paths_preserve_root_slash() {
		assert_eq!(
			inserted_well_known("/.well-known/oauth-protected-resource", "/"),
			"/.well-known/oauth-protected-resource/"
		);
		assert_eq!(
			inserted_well_known("/.well-known/oauth-protected-resource", "/mcp"),
			"/.well-known/oauth-protected-resource/mcp"
		);
	}

	#[test]
	fn configured_root_identities_remain_distinct() {
		let without_slash =
			IdentityUri::from_configured("https://gateway.example", "resource").expect("identity");
		let with_slash =
			IdentityUri::from_configured("https://gateway.example/", "resource").expect("identity");
		assert_eq!(without_slash.path(), "");
		assert_eq!(with_slash.path(), "/");
		assert_eq!(
			url_with_path(
				&without_slash,
				&inserted_well_known(
					"/.well-known/oauth-protected-resource",
					without_slash.path()
				)
			),
			"https://gateway.example/.well-known/oauth-protected-resource"
		);
		assert_eq!(
			url_with_path(
				&with_slash,
				&inserted_well_known("/.well-known/oauth-protected-resource", with_slash.path())
			),
			"https://gateway.example/.well-known/oauth-protected-resource/"
		);
	}

	#[test]
	fn ownership_is_exact_and_origin_bound() {
		let auth = auth(Some("https://gateway.example/mcp"), Some(McpIDP::Entra {}));
		for (uri, expected) in [
			(
				"https://gateway.example/.well-known/oauth-protected-resource/mcp",
				Some(McpEndpoint::ProtectedResourceMetadata),
			),
			(
				"https://gateway.example/.well-known/oauth-authorization-server/mcp",
				Some(McpEndpoint::AuthorizationServerMetadata),
			),
			(
				"https://gateway.example/mcp/authorize",
				Some(McpEndpoint::Authorization),
			),
			(
				"https://gateway.example/mcp/token",
				Some(McpEndpoint::Token),
			),
			("https://gateway.example/mcp/token-evil", None),
			("https://gateway.example/api/v1/token", None),
			("https://other.example/mcp/token", None),
		] {
			let request = request(uri, crate::types::agent::PathMatch::PathPrefix("/".into()));
			let identity = ResolvedMcpIdentity::resolve(&request, &auth).expect("identity");
			assert_eq!(
				identity.endpoint(&request, auth.provider.as_ref()),
				expected,
				"{uri}"
			);
		}
	}

	#[test]
	fn dynamic_discovery_requires_an_exact_route_context() {
		let auth = auth(None, None);
		let uri = "https://gateway.example/.well-known/oauth-protected-resource/mcp";
		let prefix = request(uri, crate::types::agent::PathMatch::PathPrefix("/".into()));
		let exact = request(
			uri,
			crate::types::agent::PathMatch::Exact("/.well-known/oauth-protected-resource/mcp".into()),
		);
		assert_eq!(
			ResolvedMcpIdentity::resolve(&prefix, &auth)
				.expect("identity")
				.endpoint(&prefix, None),
			None
		);
		assert_eq!(
			ResolvedMcpIdentity::resolve(&exact, &auth)
				.expect("identity")
				.endpoint(&exact, None),
			Some(McpEndpoint::ProtectedResourceMetadata)
		);
	}

	#[test]
	fn generic_discovery_passthrough_requires_the_explicit_resource_relative_route() {
		let auth = auth(Some("https://gateway.example/mcp"), None);
		let path = "/.well-known/oauth-authorization-server/mcp";
		let exact = request(
			&format!("https://gateway.example{path}"),
			crate::types::agent::PathMatch::Exact(path.into()),
		);
		let prefix = request(
			&format!("https://gateway.example{path}"),
			crate::types::agent::PathMatch::PathPrefix("/.well-known".into()),
		);

		let identity = ResolvedMcpIdentity::resolve(&exact, &auth).expect("identity");
		assert_eq!(
			identity.endpoint(&exact, None),
			Some(McpEndpoint::AuthorizationServerMetadata)
		);
		assert_eq!(
			identity.public_authorization_server.as_str(),
			"https://discovery.example/tenant"
		);
		assert_eq!(
			ResolvedMcpIdentity::resolve(&prefix, &auth)
				.expect("identity")
				.endpoint(&prefix, None),
			None
		);
	}

	#[test]
	fn direct_adapter_operations_infer_the_resource_path() {
		let auth = auth(None, Some(McpIDP::Entra {}));
		for (suffix, endpoint) in [
			("authorize", McpEndpoint::Authorization),
			("token", McpEndpoint::Token),
			("client-registration", McpEndpoint::Registration),
		] {
			let path = format!("/mcp/{suffix}");
			let request = request(
				&format!("https://gateway.example{path}"),
				crate::types::agent::PathMatch::Exact(path.into()),
			);
			let identity = ResolvedMcpIdentity::resolve(&request, &auth).expect("identity");
			assert_eq!(
				identity.public_resource.as_str(),
				"https://gateway.example/mcp"
			);
			assert_eq!(
				identity.endpoint(&request, auth.provider.as_ref()),
				Some(endpoint)
			);
		}
	}

	#[test]
	fn legacy_alias_requires_an_exact_route_and_rewrites_keep_public_identity() {
		let auth = auth(Some("https://gateway.example/mcp"), Some(McpIDP::Entra {}));
		let alias = "/.well-known/oauth-authorization-server/mcp/token";
		let prefix = request(
			&format!("https://gateway.example{alias}"),
			crate::types::agent::PathMatch::PathPrefix(
				"/.well-known/oauth-authorization-server/mcp".into(),
			),
		);
		assert_eq!(
			ResolvedMcpIdentity::resolve(&prefix, &auth)
				.expect("identity")
				.endpoint(&prefix, auth.provider.as_ref()),
			None
		);

		let mut rewritten = request(
			"http://backend.internal/token",
			crate::types::agent::PathMatch::Exact(alias.into()),
		);
		rewritten.extensions_mut().insert(filters::OriginalUrl(
			format!("https://gateway.example{alias}")
				.parse()
				.expect("original URL"),
		));
		assert_eq!(
			ResolvedMcpIdentity::resolve(&rewritten, &auth)
				.expect("identity")
				.endpoint(&rewritten, auth.provider.as_ref()),
			Some(McpEndpoint::Token)
		);
	}

	#[test]
	fn explicit_origin_root_authorization_server_owns_root_auth0_operations() {
		let mut auth = auth(Some("https://gateway.example/mcp"), Some(McpIDP::Auth0 {}));
		auth.resource_metadata.extra.insert(
			"authorizationServers".to_string(),
			serde_json::json!(["https://gateway.example"]),
		);
		for (path, endpoint) in [
			("/authorize", McpEndpoint::Authorization),
			("/token", McpEndpoint::Token),
			("/client-registration", McpEndpoint::Registration),
		] {
			let request = request(
				&format!("https://gateway.example{path}"),
				crate::types::agent::PathMatch::Exact(path.into()),
			);
			let identity = ResolvedMcpIdentity::resolve(&request, &auth).expect("identity");
			assert_eq!(
				identity.endpoint(&request, auth.provider.as_ref()),
				Some(endpoint)
			);
		}
	}

	#[test]
	fn identity_rejects_unsafe_components() {
		for value in [
			"http://example.com/mcp",
			"https://user@example.com/mcp",
			"https://example.com/mcp?debug=true",
			"https://example.com/a/../mcp",
		] {
			assert!(validate_identity_uri(value, "test").is_err(), "{value}");
		}
	}
}
