use http::Uri;

use crate::http::oauth::{
	authorization_server_metadata_url, entra_endpoints, openid_configuration_metadata_url,
};
use crate::json;
use crate::types::agent::McpIDP;

/// Provider-specific MCP OAuth behavior derived from the configured identity provider.
#[derive(Clone, Copy)]
pub(crate) struct McpProviderProfile<'a> {
	provider: Option<&'a McpIDP>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceParameterHandling {
	Forward,
	AudienceQueryFallback,
	Strip,
}

impl<'a> McpProviderProfile<'a> {
	pub(crate) fn new(provider: Option<&'a McpIDP>) -> Self {
		Self { provider }
	}

	pub(crate) fn rewrites_public_issuer(self) -> bool {
		match self.provider {
			None => false,
			Some(
				McpIDP::Auth0 {}
				| McpIDP::Keycloak {}
				| McpIDP::Okta {}
				| McpIDP::Descope {}
				| McpIDP::Authentik {}
				| McpIDP::Entra {},
			) => true,
		}
	}

	pub(crate) fn proxies_oauth_endpoints(self) -> bool {
		match self.provider {
			Some(McpIDP::Entra {}) => true,
			None
			| Some(
				McpIDP::Auth0 {}
				| McpIDP::Keycloak {}
				| McpIDP::Okta {}
				| McpIDP::Descope {}
				| McpIDP::Authentik {},
			) => false,
		}
	}

	pub(crate) fn metadata_url(self, issuer: &str) -> Result<String, String> {
		match self.provider {
			None | Some(McpIDP::Auth0 {}) => Ok(authorization_server_metadata_url(issuer)),
			Some(McpIDP::Keycloak {} | McpIDP::Okta {} | McpIDP::Descope {} | McpIDP::Authentik {}) => {
				Ok(openid_configuration_metadata_url(issuer))
			},
			Some(McpIDP::Entra {}) => Ok(entra_endpoints(issuer)?.openid_configuration),
		}
	}

	pub(crate) fn jwks_url(self, issuer: &str) -> Result<Uri, String> {
		let url = match self.provider {
			None | Some(McpIDP::Auth0 {} | McpIDP::Okta {}) => {
				format!("{issuer}/.well-known/jwks.json")
			},
			Some(McpIDP::Keycloak {}) => {
				format!("{issuer}/protocol/openid-connect/certs")
			},
			Some(McpIDP::Authentik {}) => {
				format!("{}/jwks/", issuer.trim_end_matches('/'))
			},
			Some(McpIDP::Entra {}) => entra_endpoints(issuer)?.jwks_uri,
			Some(McpIDP::Descope {}) => descope_jwks_url(issuer)?,
		};
		url
			.parse()
			.map_err(|error| format!("invalid JWKS URL: {error}"))
	}

	pub(crate) fn registration_url(self, issuer: &str) -> Result<String, String> {
		let issuer = issuer.trim_end_matches('/');
		match self.provider {
			None | Some(McpIDP::Auth0 {} | McpIDP::Keycloak {}) => {
				Ok(format!("{issuer}/clients-registrations/openid-connect"))
			},
			Some(McpIDP::Okta {}) => {
				let parsed = parse_issuer(issuer)?;
				Ok(format!(
					"{}/oauth2/v1/clients",
					parsed.origin().ascii_serialization()
				))
			},
			Some(McpIDP::Descope {}) => descope_registration_url(issuer),
			Some(McpIDP::Authentik {}) => Err(
				// https://github.com/goauthentik/authentik/issues/8751
				"authentik does not support Dynamic Client Registration; set clientId to a pre-registered public client".to_string(),
			),
			Some(McpIDP::Entra {}) => Err(
				"Entra ID does not support Dynamic Client Registration (RFC 7591); set `clientId` on mcpAuthentication to a pre-registered app registration".to_string(),
			),
		}
	}

	pub(crate) fn rewrite_metadata(
		self,
		metadata: &mut serde_json::Value,
		public_metadata_uri: &str,
		audiences: &[String],
	) -> Result<(), String> {
		if self.resource_parameter_handling() == ResourceParameterHandling::AudienceQueryFallback {
			append_audience(metadata, audiences)?;
		}
		match self.provider {
			None => Ok(()),
			// These are compatibility defaults. Some Auth0 and Okta tenants support native
			// resource indicators, which later provider work can expose as a capability.
			Some(McpIDP::Auth0 {}) => Ok(()),
			Some(McpIDP::Okta {}) => {
				rewrite_registration_if_present(metadata, public_metadata_uri);
				Ok(())
			},
			Some(McpIDP::Descope {}) => {
				rewrite_registration_if_present(metadata, public_metadata_uri);
				Ok(())
			},
			Some(McpIDP::Keycloak {}) => {
				// Keycloak needs its audience configured on the server today
				// https://github.com/keycloak/keycloak/issues/10169
				// https://github.com/keycloak/keycloak/issues/14355
				// Keycloak registration lacks browser CORS support
				// https://github.com/keycloak/keycloak/issues/39629
				let registration = required_string(metadata, "registration_endpoint")?;
				*registration = gateway_registration_url(public_metadata_uri);
				Ok(())
			},
			Some(McpIDP::Authentik {}) => {
				if let Some(object) = metadata.as_object_mut() {
					object.insert(
						"registration_endpoint".to_string(),
						gateway_registration_url(public_metadata_uri).into(),
					);
				}
				Ok(())
			},
			Some(McpIDP::Entra {}) => {
				*required_string(metadata, "authorization_endpoint")? =
					format!("{public_metadata_uri}/authorize");
				*required_string(metadata, "token_endpoint")? = format!("{public_metadata_uri}/token");
				let object = metadata
					.as_object_mut()
					.ok_or_else(|| "authorization server metadata must be a JSON object".to_string())?;
				object.insert(
					"registration_endpoint".to_string(),
					gateway_registration_url(public_metadata_uri).into(),
				);
				object
					.entry("code_challenge_methods_supported")
					.or_insert_with(|| serde_json::json!(["S256"]));
				Ok(())
			},
		}
	}

	pub(crate) fn authorization_endpoint(self, issuer: &str) -> Result<Option<String>, String> {
		match self.provider {
			Some(McpIDP::Entra {}) => Ok(Some(entra_endpoints(issuer)?.authorization_endpoint)),
			None
			| Some(
				McpIDP::Auth0 {}
				| McpIDP::Keycloak {}
				| McpIDP::Okta {}
				| McpIDP::Descope {}
				| McpIDP::Authentik {},
			) => Ok(None),
		}
	}

	pub(crate) fn token_endpoint(self, issuer: &str) -> Result<Option<String>, String> {
		match self.provider {
			Some(McpIDP::Entra {}) => Ok(Some(entra_endpoints(issuer)?.token_endpoint)),
			None
			| Some(
				McpIDP::Auth0 {}
				| McpIDP::Keycloak {}
				| McpIDP::Okta {}
				| McpIDP::Descope {}
				| McpIDP::Authentik {},
			) => Ok(None),
		}
	}

	pub(crate) fn strips_resource_parameter(self) -> bool {
		self.resource_parameter_handling() == ResourceParameterHandling::Strip
	}

	/// The gateway credential may only be attached to Entra's delegated user grants.
	/// This endpoint is reachable before MCP authentication, so other providers and grant
	/// types must never receive the configured secret.
	pub(crate) fn may_inject_client_secret(self, grant_type: Option<&str>) -> bool {
		match self.provider {
			Some(McpIDP::Entra {}) => {
				matches!(grant_type, Some("authorization_code" | "refresh_token"))
			},
			None
			| Some(
				McpIDP::Auth0 {}
				| McpIDP::Keycloak {}
				| McpIDP::Okta {}
				| McpIDP::Descope {}
				| McpIDP::Authentik {},
			) => false,
		}
	}

	fn resource_parameter_handling(self) -> ResourceParameterHandling {
		match self.provider {
			Some(McpIDP::Auth0 {} | McpIDP::Okta {}) => ResourceParameterHandling::AudienceQueryFallback,
			Some(McpIDP::Entra {}) => ResourceParameterHandling::Strip,
			None | Some(McpIDP::Keycloak {} | McpIDP::Descope {} | McpIDP::Authentik {}) => {
				ResourceParameterHandling::Forward
			},
		}
	}
}

fn append_audience(metadata: &mut serde_json::Value, audiences: &[String]) -> Result<(), String> {
	let authorization_endpoint = required_string(metadata, "authorization_endpoint")?;
	if let Some(audience) = audiences.first() {
		authorization_endpoint.push_str(&format!("?audience={audience}"));
	}
	Ok(())
}

fn required_string<'a>(
	metadata: &'a mut serde_json::Value,
	field: &'static str,
) -> Result<&'a mut String, String> {
	match json::traverse_mut(metadata, &[field]) {
		Some(serde_json::Value::String(value)) => Ok(value),
		_ => Err(format!("{field} missing")),
	}
}

fn rewrite_registration_if_present(metadata: &mut serde_json::Value, public_metadata_uri: &str) {
	if let Some(serde_json::Value::String(endpoint)) =
		json::traverse_mut(metadata, &["registration_endpoint"])
	{
		*endpoint = gateway_registration_url(public_metadata_uri);
	}
}

fn gateway_registration_url(public_metadata_uri: &str) -> String {
	format!("{public_metadata_uri}/client-registration")
}

fn parse_issuer(issuer: &str) -> Result<url::Url, String> {
	issuer
		.parse()
		.map_err(|error| format!("invalid issuer URL: {error}"))
}

fn descope_jwks_url(issuer: &str) -> Result<String, String> {
	let parsed = parse_issuer(issuer)?;
	let segments: Vec<&str> = parsed.path().trim_start_matches('/').split('/').collect();
	if segments.len() >= 5 && segments[0] == "v1" && segments[1] == "apps" && segments[2] == "agentic"
	{
		Ok(format!(
			"{}/{}/.well-known/jwks.json",
			parsed.origin().ascii_serialization(),
			segments[3]
		))
	} else {
		Ok(format!("{issuer}/.well-known/jwks.json"))
	}
}

fn descope_registration_url(issuer: &str) -> Result<String, String> {
	let parsed = parse_issuer(issuer)?;
	let segments: Vec<&str> = parsed.path().trim_start_matches('/').split('/').collect();
	if segments.len() >= 5 && segments[0] == "v1" && segments[1] == "apps" && segments[2] == "agentic"
	{
		Ok(format!(
			"{}/v1/mgmt/mcp/client/{}/{}/register",
			parsed.origin().ascii_serialization(),
			segments[3],
			segments[4]
		))
	} else {
		Err("Descope DCR requires an agentic issuer URL".to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn profile(provider: Option<&McpIDP>) -> McpProviderProfile<'_> {
		McpProviderProfile::new(provider)
	}

	#[test]
	fn discovery_and_jwks_urls_are_explicit_for_every_provider() {
		let auth0 = McpIDP::Auth0 {};
		let keycloak = McpIDP::Keycloak {};
		let okta = McpIDP::Okta {};
		let descope = McpIDP::Descope {};
		let authentik = McpIDP::Authentik {};
		let entra = McpIDP::Entra {};

		let cases = [
			(
				profile(None),
				"https://idp.example.com/tenant",
				"https://idp.example.com/.well-known/oauth-authorization-server/tenant",
				"https://idp.example.com/tenant/.well-known/jwks.json",
			),
			(
				profile(Some(&auth0)),
				"https://tenant.auth0.com",
				"https://tenant.auth0.com/.well-known/oauth-authorization-server",
				"https://tenant.auth0.com/.well-known/jwks.json",
			),
			(
				profile(Some(&keycloak)),
				"https://idp.example.com/realms/demo",
				"https://idp.example.com/realms/demo/.well-known/openid-configuration",
				"https://idp.example.com/realms/demo/protocol/openid-connect/certs",
			),
			(
				profile(Some(&okta)),
				"https://tenant.okta.com/oauth2/default",
				"https://tenant.okta.com/oauth2/default/.well-known/openid-configuration",
				"https://tenant.okta.com/oauth2/default/.well-known/jwks.json",
			),
			(
				profile(Some(&descope)),
				"https://api.descope.com/v1/apps/agentic/project/server",
				"https://api.descope.com/v1/apps/agentic/project/server/.well-known/openid-configuration",
				"https://api.descope.com/project/.well-known/jwks.json",
			),
			(
				profile(Some(&authentik)),
				"https://auth.example.com/application/o/mcp/",
				"https://auth.example.com/application/o/mcp/.well-known/openid-configuration",
				"https://auth.example.com/application/o/mcp/jwks/",
			),
			(
				profile(Some(&entra)),
				"https://sts.windows.net/tenant-id/",
				"https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration",
				"https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
			),
		];

		for (provider, issuer, expected_metadata, expected_jwks) in cases {
			assert_eq!(provider.metadata_url(issuer).unwrap(), expected_metadata);
			assert_eq!(
				provider.jwks_url(issuer).unwrap().to_string(),
				expected_jwks
			);
		}
	}

	#[test]
	fn upstream_registration_is_explicit_for_every_provider() {
		let auth0 = McpIDP::Auth0 {};
		let keycloak = McpIDP::Keycloak {};
		let okta = McpIDP::Okta {};
		let descope = McpIDP::Descope {};
		let authentik = McpIDP::Authentik {};
		let entra = McpIDP::Entra {};

		assert_eq!(
			profile(None)
				.registration_url("https://idp.example.com/issuer/")
				.unwrap(),
			"https://idp.example.com/issuer/clients-registrations/openid-connect"
		);
		// This Auth0 fallback is a known defect retained until work 06.
		assert_eq!(
			profile(Some(&auth0))
				.registration_url("https://tenant.auth0.com")
				.unwrap(),
			"https://tenant.auth0.com/clients-registrations/openid-connect"
		);
		assert_eq!(
			profile(Some(&keycloak))
				.registration_url("https://idp.example.com/realms/demo")
				.unwrap(),
			"https://idp.example.com/realms/demo/clients-registrations/openid-connect"
		);
		assert_eq!(
			profile(Some(&okta))
				.registration_url("https://tenant.okta.com/oauth2/default")
				.unwrap(),
			"https://tenant.okta.com/oauth2/v1/clients"
		);
		assert_eq!(
			profile(Some(&descope))
				.registration_url("https://api.descope.com/v1/apps/agentic/project/server")
				.unwrap(),
			"https://api.descope.com/v1/mgmt/mcp/client/project/server/register"
		);
		assert!(
			profile(Some(&authentik))
				.registration_url("https://auth.example.com")
				.is_err()
		);
		assert!(
			profile(Some(&entra))
				.registration_url("https://login.microsoftonline.com/t/v2.0")
				.is_err()
		);
	}

	#[test]
	fn metadata_rewrites_are_explicit_for_every_provider() {
		let auth0 = McpIDP::Auth0 {};
		let keycloak = McpIDP::Keycloak {};
		let okta = McpIDP::Okta {};
		let descope = McpIDP::Descope {};
		let authentik = McpIDP::Authentik {};
		let entra = McpIDP::Entra {};
		let public_uri = "https://gateway.example.com/.well-known/oauth-authorization-server/mcp";
		let audiences = vec!["api://mcp".to_string()];
		let original = serde_json::json!({
			"authorization_endpoint": "https://idp.example.com/authorize",
			"token_endpoint": "https://idp.example.com/token",
			"registration_endpoint": "https://idp.example.com/register"
		});

		let mut generic = original.clone();
		profile(None)
			.rewrite_metadata(&mut generic, public_uri, &audiences)
			.unwrap();
		assert_eq!(generic, original);

		for provider in [profile(Some(&auth0)), profile(Some(&okta))] {
			let mut metadata = original.clone();
			provider
				.rewrite_metadata(&mut metadata, public_uri, &audiences)
				.unwrap();
			assert_eq!(
				metadata["authorization_endpoint"],
				"https://idp.example.com/authorize?audience=api://mcp"
			);
		}

		for provider in [
			profile(Some(&keycloak)),
			profile(Some(&okta)),
			profile(Some(&descope)),
		] {
			let mut metadata = original.clone();
			provider
				.rewrite_metadata(&mut metadata, public_uri, &audiences)
				.unwrap();
			assert_eq!(
				metadata["registration_endpoint"],
				format!("{public_uri}/client-registration")
			);
		}

		let mut metadata = original.clone();
		profile(Some(&authentik))
			.rewrite_metadata(&mut metadata, public_uri, &audiences)
			.unwrap();
		assert_eq!(
			metadata["registration_endpoint"],
			format!("{public_uri}/client-registration")
		);

		let mut metadata = original;
		profile(Some(&entra))
			.rewrite_metadata(&mut metadata, public_uri, &audiences)
			.unwrap();
		assert_eq!(
			metadata["authorization_endpoint"],
			format!("{public_uri}/authorize")
		);
		assert_eq!(metadata["token_endpoint"], format!("{public_uri}/token"));
		assert_eq!(
			metadata["registration_endpoint"],
			format!("{public_uri}/client-registration")
		);
		assert_eq!(
			metadata["code_challenge_methods_supported"],
			serde_json::json!(["S256"])
		);
	}

	#[test]
	fn only_entra_proxies_oauth_and_injects_delegated_credentials() {
		let providers = [
			McpIDP::Auth0 {},
			McpIDP::Keycloak {},
			McpIDP::Okta {},
			McpIDP::Descope {},
			McpIDP::Authentik {},
		];
		assert!(!profile(None).proxies_oauth_endpoints());
		for provider in &providers {
			assert!(!profile(Some(provider)).proxies_oauth_endpoints());
			assert!(!profile(Some(provider)).may_inject_client_secret(Some("authorization_code")));
		}

		let entra = McpIDP::Entra {};
		let entra = profile(Some(&entra));
		assert!(entra.proxies_oauth_endpoints());
		assert!(entra.strips_resource_parameter());
		assert!(entra.may_inject_client_secret(Some("authorization_code")));
		assert!(entra.may_inject_client_secret(Some("refresh_token")));
		assert!(!entra.may_inject_client_secret(Some("client_credentials")));
	}
}
