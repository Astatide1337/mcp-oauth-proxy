import os
import time
import unittest

os.environ.update({
    "PUBLIC_BASE_URL": "https://proxy.example.invalid",
    "CLOUDFLARE_TEAM_DOMAIN": "team.example.invalid",
    "CLOUDFLARE_AUD": "test-audience",
    "LOCAL_TOKEN_SECRET": "test-only-not-a-real-secret",
    "PYTHON_DOTENV_DISABLED": "1",
})

import server
from starlette.testclient import TestClient


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.mcp.http_app(path="/mcp"))

    def test_authorization_metadata_preserves_exact_issuer(self):
        response = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["issuer"], "https://proxy.example.invalid")
        self.assertEqual(response.json()["token_endpoint"], "https://proxy.example.invalid/token")
        self.assertEqual(response.json()["code_challenge_methods_supported"], ["S256"])

    def test_protected_resource_metadata_preserves_exact_issuer(self):
        response = self.client.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["authorization_servers"], ["https://proxy.example.invalid"])
        self.assertEqual(response.json()["resource"], "https://proxy.example.invalid/mcp")

    def test_anonymous_request_stays_unauthorized(self):
        response = self.client.get("/mcp")
        self.assertEqual(response.status_code, 401)
        self.assertIn("resource_metadata=", response.headers["www-authenticate"])

    def test_invalid_token_stays_unauthorized(self):
        response = self.client.get("/mcp", headers={"Authorization": "Bearer invalid-fixture-token"})
        self.assertEqual(response.status_code, 401)

    def test_metadata_keeps_cors_support(self):
        for path in (
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            with self.subTest(path=path):
                response = self.client.get(path, headers={"Origin": "https://client.example.invalid"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["access-control-allow-origin"], "*")


class LocalTokenTests(unittest.IsolatedAsyncioTestCase):
    async def test_unexpired_local_token_is_accepted(self):
        provider = server.CloudflareAccessOAuthProvider()
        token = server.AccessToken(
            token="local-fixture-token", client_id="fixture-client",
            scopes=["mcp"], expires_at=int(time.time()) + 60,
        )
        provider._access_tokens[token.token] = token
        self.assertIs(await provider.load_access_token(token.token), token)

    async def test_expired_local_token_is_rejected(self):
        provider = server.CloudflareAccessOAuthProvider()
        token = server.AccessToken(
            token="expired-fixture-token", client_id="fixture-client",
            scopes=["mcp"], expires_at=int(time.time()) - 60,
        )
        provider._access_tokens[token.token] = token
        self.assertIsNone(await provider.load_access_token(token.token))


if __name__ == "__main__":
    unittest.main()
