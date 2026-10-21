"""Offline tests for the scan-target SSRF guard."""
import socket
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from engines import net_guard, security_engine
from engines.net_guard import BlockedDestinationError, PublicOnlyTransport, is_public_address, resolve_public_address
from routers import scan
from tests.auth_helpers import authenticated_client

PUBLIC_IP = "93.184.216.34"


def _fake_getaddrinfo(mapping):
    def getaddrinfo(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(f"unknown host {host}")
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
            for address in mapping[host]
        ]
    return getaddrinfo


class AddressClassificationTests(unittest.TestCase):
    def test_non_public_addresses_are_rejected(self):
        for address in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
            "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:7f00:1::", "fe80::1%eth0", "not-an-ip",
        ]:
            with self.subTest(address=address):
                self.assertFalse(is_public_address(address))

    def test_public_addresses_are_allowed(self):
        for address in [PUBLIC_IP, "1.1.1.1", "2606:4700:4700::1111"]:
            with self.subTest(address=address):
                self.assertTrue(is_public_address(address))

    def test_host_with_any_private_address_is_blocked(self):
        mapping = {"mixed.example": [PUBLIC_IP, "10.0.0.5"]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)):
            with self.assertRaises(BlockedDestinationError):
                resolve_public_address("mixed.example", 443)

    def test_public_host_resolves_to_its_address(self):
        mapping = {"public.example": [PUBLIC_IP]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)):
            self.assertEqual(resolve_public_address("public.example", 443), PUBLIC_IP)


class PublicOnlyTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_is_pinned_to_the_checked_address(self):
        sent = []

        async def fake_send(self, request):
            sent.append(request)
            return httpx.Response(200, request=request)

        mapping = {"public.example": [PUBLIC_IP]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)), \
             patch.object(httpx.AsyncHTTPTransport, "handle_async_request", fake_send):
            async with httpx.AsyncClient(transport=PublicOnlyTransport()) as client:
                response = await client.get("https://public.example/path?q=1")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(response.request.url), "https://public.example/path?q=1")
        self.assertEqual(sent[0].url.host, PUBLIC_IP)
        self.assertEqual(sent[0].url.path, "/path")
        self.assertEqual(sent[0].headers["host"], "public.example")
        self.assertEqual(sent[0].extensions["sni_hostname"], "public.example")

    async def test_private_target_is_never_contacted(self):
        base_send = AsyncMock()
        mapping = {"internal.example": ["127.0.0.1"]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)), \
             patch.object(httpx.AsyncHTTPTransport, "handle_async_request", base_send):
            async with httpx.AsyncClient(transport=PublicOnlyTransport()) as client:
                with self.assertRaises(BlockedDestinationError):
                    await client.get("http://internal.example/")
        base_send.assert_not_awaited()

    async def test_redirect_to_metadata_endpoint_is_blocked(self):
        sent = []

        async def fake_send(self, request):
            sent.append(request)
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"}, request=request
            )

        mapping = {"evil.example": [PUBLIC_IP], "169.254.169.254": ["169.254.169.254"]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)), \
             patch.object(httpx.AsyncHTTPTransport, "handle_async_request", fake_send):
            async with httpx.AsyncClient(transport=PublicOnlyTransport(), follow_redirects=True) as client:
                with self.assertRaises(BlockedDestinationError):
                    await client.get("http://evil.example/")
        self.assertEqual(len(sent), 1)


class SslCheckGuardTests(unittest.TestCase):
    def test_ssl_check_refuses_private_targets(self):
        mapping = {"internal.example": ["10.0.0.5"]}
        with patch.object(net_guard.socket, "getaddrinfo", _fake_getaddrinfo(mapping)), \
             patch.object(security_engine.socket, "create_connection") as connect:
            info = security_engine.get_ssl_info("internal.example")
        connect.assert_not_called()
        self.assertFalse(info.valid)
        self.assertIn("non-public address", info.vulnerabilities[0])


class ScanStartGuardTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from engines import scan_store
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_patch = patch.object(scan_store, "DB_PATH", Path(self.temp_dir.name) / "scans.db")
        self.store_patch.start()
        scan_store.init_db()
        self.client = authenticated_client()

    def tearDown(self):
        self.client.close()
        self.store_patch.stop()
        self.temp_dir.cleanup()

    def test_scan_of_privately_resolving_domain_is_refused(self):
        blocked = BlockedDestinationError("internal.example resolves to a non-public address")
        with patch.object(scan, "resolve_public_address", side_effect=blocked), \
             patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "internal.example", "authorized": True},
            )
        self.assertEqual(response.status_code, 422)
        self.assertIn("private or reserved", response.json()["detail"])
        run_scan.assert_not_awaited()

    def test_unresolvable_domain_can_still_be_scanned(self):
        with patch.object(scan, "resolve_public_address", side_effect=socket.gaierror("no such host")), \
             patch.object(scan, "run_scan", new=AsyncMock()) as run_scan:
            response = self.client.post(
                "/api/scan/start",
                json={"domain": "unregistered-example.com", "authorized": True},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "started")


if __name__ == "__main__":
    unittest.main()
