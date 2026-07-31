import logging
import os
import secrets
import time
import types
from urllib.parse import urlencode

import jwt
from starlette.responses import JSONResponse
from fastmcp.server.auth.middleware import RequireAuthMiddleware
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import AuthorizationCode, AuthorizationParams, OAuthToken, RefreshToken
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull
from mcp.server.auth.middleware.client_auth import AuthenticationError, ClientAuthenticator
from mcp.server.auth.handlers.token import (
    AuthorizationCodeRequest, PydanticJSONResponse, RefreshTokenRequest,
    TokenError, TokenErrorResponse, TokenHandler, TokenRequest,
    TokenSuccessResponse, stringify_pydantic_error,
)
from pydantic import ValidationError

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-proxy-auth")

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")
MCP_PATH = os.getenv("MCP_PATH", "/mcp")
CLOUDFLARE_TEAM_DOMAIN = os.getenv("CLOUDFLARE_TEAM_DOMAIN")
CLOUDFLARE_AUD = os.getenv("CLOUDFLARE_AUD")
LOCAL_TOKEN_SECRET = os.getenv("LOCAL_TOKEN_SECRET")

if not all([PUBLIC_BASE_URL, CLOUDFLARE_TEAM_DOMAIN, CLOUDFLARE_AUD, LOCAL_TOKEN_SECRET]):
    raise RuntimeError("Missing required env vars: PUBLIC_BASE_URL, CLOUDFLARE_TEAM_DOMAIN, CLOUDFLARE_AUD, LOCAL_TOKEN_SECRET")


class CloudflareAccessOAuthProvider(OAuthProvider):
    def __init__(self) -> None:
        super().__init__(
            base_url=PUBLIC_BASE_URL,
            resource_base_url=PUBLIC_BASE_URL,
            issuer_url=PUBLIC_BASE_URL,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=["mcp"],
                default_scopes=["mcp"],
            ),
        )
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._jwks_client = jwt.PyJWKClient(
            f"https://{CLOUDFLARE_TEAM_DOMAIN}/cdn-cgi/access/certs"
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id not in self._clients:
            client = OAuthClientInformationFull(
                client_id=client_id,
                client_name="Client",
                redirect_uris=[
                    "https://chatgpt.com/aip/mcp/oauth/callback",
                    "https://claude.ai/api/mcp/auth_callback",
                ],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="none",
            )
            class PermissiveClient(OAuthClientInformationFull):
                def validate_redirect_uri(self, redirect_uri):
                    known_prefixes = ("https://chatgpt.com/aip/", "https://chatgpt.com/connector/oauth/", "https://claude.ai/")
                    if redirect_uri is not None:
                        uri = str(redirect_uri)
                        if any(uri.startswith(p) for p in known_prefixes):
                            return redirect_uri
                        raise InvalidRedirectUriError(f"Redirect URI '{redirect_uri}' not registered")
                    return self.redirect_uris[0]
            client.__class__ = PermissiveClient
            self._clients[client_id] = client
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            client_info.client_id = secrets.token_urlsafe(32)
        client_info.client_id_issued_at = int(time.time())
        self._clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or ["mcp"],
            expires_at=time.time() + 300,
            client_id=client.client_id,
            code_challenge=params.code_challenge or "",
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="cloudflare-access-user",
        )
        query = {"code": code}
        if params.state:
            query["state"] = params.state
        return f"{params.redirect_uri}?{urlencode(query)}"

    async def load_authorization_code(self, client, authorization_code: str) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if not code or code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)
        access_token = secrets.token_urlsafe(48)
        refresh_token = secrets.token_urlsafe(48)
        expires_in = 3600
        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + expires_in,
            resource=f"{PUBLIC_BASE_URL}{MCP_PATH}",
            subject=authorization_code.subject,
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 30 * 24 * 3600,
            subject=authorization_code.subject,
        )
        return OAuthToken(
            access_token=access_token,
            expires_in=expires_in,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        local_token = self._access_tokens.get(token)
        if local_token and (local_token.expires_at is None or local_token.expires_at > time.time()):
            return local_token
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(token, signing_key.key, algorithms=["RS256"],
                                audience=CLOUDFLARE_AUD,
                                issuer=f"https://{CLOUDFLARE_TEAM_DOMAIN}")
        except jwt.PyJWTError:
            return None
        return AccessToken(
            token=token,
            client_id=claims.get("email") or claims.get("sub") or "cloudflare-access",
            scopes=["mcp"],
            expires_at=claims.get("exp"),
            subject=claims.get("sub"),
        )

    async def load_refresh_token(self, client, refresh_token: str) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if not token or token.client_id != client.client_id:
            return None
        if token.expires_at and token.expires_at < time.time():
            return None
        return token

    async def exchange_refresh_token(self, client, refresh_token, scopes) -> OAuthToken:
        expires_in = 3600
        token_scopes = scopes or refresh_token.scopes
        access_token = secrets.token_urlsafe(48)
        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=token_scopes,
            expires_at=int(time.time()) + expires_in,
            resource=f"{PUBLIC_BASE_URL}{MCP_PATH}",
            subject=refresh_token.subject,
        )
        return OAuthToken(access_token=access_token, expires_in=expires_in,
                          scope=" ".join(token_scopes))

    async def revoke_token(self, token) -> None:
        self._access_tokens.pop(getattr(token, "token", None), None)
        self._refresh_tokens.pop(getattr(token, "token", None), None)


async def _authenticate_request_accept_basic_client_id(self, request):
    import base64
    from urllib.parse import unquote
    form_data = await request.form()
    client_id = form_data.get("client_id")
    auth_header = request.headers.get("Authorization", "")
    if not client_id and auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            basic_client_id, _ = decoded.split(":", 1)
            client_id = unquote(basic_client_id)
        except Exception as exc:
            raise AuthenticationError("Invalid Basic authentication header") from exc
    if not client_id:
        raise AuthenticationError("Missing client_id")
    client = await self.provider.get_client(str(client_id))
    if not client:
        raise AuthenticationError("Invalid client_id")
    if client.client_secret:
        return await _ORIGINAL_AUTHENTICATE_REQUEST(self, request)
    return client


async def _token_handle_accept_basic_client_id(self, request):
    import base64, hashlib
    try:
        client_info = await self.client_authenticator.authenticate_request(request)
    except AuthenticationError as e:
        logger.warning("token auth failed: %s", e.message)
        return PydanticJSONResponse(
            content=TokenErrorResponse(error="unauthorized_client", error_description=e.message),
            status_code=401,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    try:
        form_data = dict(await request.form())
        logger.info("token form_data: %s", {k: v for k, v in form_data.items() if k != "client_secret"})
        form_data.setdefault("client_id", client_info.client_id)
        token_request = TokenRequest.model_validate(form_data).root
    except ValidationError as e:
        logger.warning("token validation error: %s", stringify_pydantic_error(e))
        return self.response(TokenErrorResponse(error="invalid_request",
                                                error_description=stringify_pydantic_error(e)))
    if token_request.grant_type not in client_info.grant_types:
        return self.response(TokenErrorResponse(error="unsupported_grant_type",
                                                error_description="Unsupported grant type"))
    match token_request:
        case AuthorizationCodeRequest():
            auth_code = await self.provider.load_authorization_code(client_info, token_request.code)
            if auth_code is None or auth_code.client_id != token_request.client_id:
                return self.response(TokenErrorResponse(error="invalid_grant",
                                                        error_description="authorization code does not exist"))
            if auth_code.expires_at < time.time():
                return self.response(TokenErrorResponse(error="invalid_grant",
                                                        error_description="authorization code has expired"))
            authorize_redirect = auth_code.redirect_uri if auth_code.redirect_uri_provided_explicitly else None
            token_redirect_str = str(token_request.redirect_uri) if token_request.redirect_uri is not None else None
            auth_redirect_str = str(authorize_redirect) if authorize_redirect is not None else None
            if token_redirect_str != auth_redirect_str:
                return self.response(TokenErrorResponse(error="invalid_request",
                                                        error_description="redirect_uri mismatch"))
            if auth_code.code_challenge is not None:
                if token_request.code_verifier is None:
                    return self.response(TokenErrorResponse(error="invalid_grant",
                                                            error_description="code_verifier required for PKCE"))
                sha256 = hashlib.sha256(token_request.code_verifier.encode()).digest()
                hashed = base64.urlsafe_b64encode(sha256).decode().rstrip("=")
                if hashed != auth_code.code_challenge:
                    return self.response(TokenErrorResponse(error="invalid_grant",
                                                            error_description="incorrect code_verifier"))
            try:
                tokens = await self.provider.exchange_authorization_code(client_info, auth_code)
            except TokenError as e:
                return self.response(TokenErrorResponse(error=e.error,
                                                        error_description=e.error_description))
        case RefreshTokenRequest():
            refresh_token = await self.provider.load_refresh_token(client_info, token_request.refresh_token)
            if refresh_token is None or refresh_token.client_id != token_request.client_id:
                return self.response(TokenErrorResponse(error="invalid_grant",
                                                        error_description="refresh token does not exist"))
            scopes = token_request.scope.split(" ") if token_request.scope else refresh_token.scopes
            try:
                tokens = await self.provider.exchange_refresh_token(client_info, refresh_token, scopes)
            except TokenError as e:
                return self.response(TokenErrorResponse(error=e.error,
                                                        error_description=e.error_description))
    token_response = {
        "access_token": tokens.access_token,
        "token_type": "Bearer",
        "expires_in": tokens.expires_in,
        "scope": tokens.scope or "mcp",
        "resource": f"{PUBLIC_BASE_URL.rstrip('/')}{MCP_PATH}",
    }
    return JSONResponse(token_response, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


async def _send_minimal_auth_error(self, send, status_code, error, description):
    import json
    resource_metadata_url = f"{PUBLIC_BASE_URL.rstrip('/')}/.well-known/oauth-protected-resource{MCP_PATH}"
    body = json.dumps({"error": error, "error_description": description}).encode()
    await send({"type": "http.response.start", "status": status_code,
                "headers": [(b"content-type", b"application/json"),
                             (b"content-length", str(len(body)).encode()),
                             (b"www-authenticate",
                              f'Bearer resource_metadata="{resource_metadata_url}"'.encode())]})
    await send({"type": "http.response.body", "body": body})


_ORIGINAL_AUTHENTICATE_REQUEST = ClientAuthenticator.authenticate_request
ClientAuthenticator.authenticate_request = _authenticate_request_accept_basic_client_id
TokenHandler.handle = _token_handle_accept_basic_client_id
RequireAuthMiddleware._send_auth_error = _send_minimal_auth_error

mcp = FastMCP.as_proxy(
    "http://localhost:8080/mcp",
    auth=CloudflareAccessOAuthProvider()
)


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server_metadata(request):
    issuer = PUBLIC_BASE_URL.rstrip("/")
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "registration_endpoint": f"{issuer}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
    }, headers={"Cache-Control": "public, max-age=3600"})


@mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def oauth_protected_resource_metadata(request):
    issuer = PUBLIC_BASE_URL.rstrip("/")
    return JSONResponse({
        "resource": f"{issuer}{MCP_PATH}",
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }, headers={"Cache-Control": "public, max-age=3600"})


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8090,
        path=MCP_PATH
    )
