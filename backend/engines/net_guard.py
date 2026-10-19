"""Outbound connection guard for scan targets.

Scan targets are user-supplied, so every connection the scanner makes must land on a
public internet address. Each hop is resolved once, every resolved address is checked,
and the connection is pinned to the checked address so a second DNS answer (rebinding)
or a redirect to an internal host cannot reach private, loopback, link-local, or
cloud-metadata endpoints.
"""
import asyncio
import ipaddress
import socket

import httpx

RESOLVE_TIMEOUT_SECONDS = 5


class BlockedDestinationError(httpx.ConnectError):
    """Raised when a scan target resolves to a non-public address."""


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        # Includes scoped IPv6 literals such as fe80::1%eth0.
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None and not is_public_address(str(embedded)):
            return False
    return ip.is_global and not ip.is_multicast


def resolve_public_address(host: str, port: int) -> str:
    """Resolve host and return one address, refusing hosts with any non-public address."""
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses or not all(is_public_address(address) for address in addresses):
        raise BlockedDestinationError(f"{host} resolves to a non-public address; the connection was blocked.")
    return addresses[0]


class PublicOnlyTransport(httpx.AsyncHTTPTransport):
    """httpx transport that pins every request (including redirect hops) to a public IP."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        try:
            address = await asyncio.wait_for(
                asyncio.to_thread(resolve_public_address, host, port),
                timeout=RESOLVE_TIMEOUT_SECONDS,
            )
        except BlockedDestinationError as exc:
            raise BlockedDestinationError(str(exc), request=request) from None
        except (socket.gaierror, asyncio.TimeoutError) as exc:
            raise httpx.ConnectError(f"Could not resolve {host}.", request=request) from exc

        # The original Host header is kept; SNI and certificate checks use the hostname.
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=address),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await super().handle_async_request(pinned)
