"""
BharatSec — Security Engine
SSL/TLS certificate and protocol analysis
"""
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from engines.net_guard import BlockedDestinationError, resolve_public_address
from models.scan_models import SSLInfo


# ── SSL / TLS Analysis ────────────────────────────────────────────────────────

LEGACY_TLS_LABELS = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}


def _legacy_tls_version(address: str, domain: str, port: int) -> Optional[str]:
    """Return "TLSv1"/"TLSv1.1" if the server still negotiates a deprecated protocol.

    The default context refuses anything below TLS 1.2, so legacy support needs its own
    probe. Returns None when the local OpenSSL build cannot offer legacy TLS at all.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((address, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                version = ssock.version()
                return version if version in LEGACY_TLS_LABELS else None
    except (OSError, ValueError, ssl.SSLError):
        return None


def get_ssl_info(domain: str, port: int = 443) -> SSLInfo:
    info = SSLInfo()
    address = None

    try:
        ctx = ssl.create_default_context()
        address = resolve_public_address(domain, port)
        with socket.create_connection((address, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info.valid = True
                info.protocol = ssock.version() or ""

                # Issuer & subject
                issuer_dict  = dict(x[0] for x in cert.get("issuer", []))
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                info.issuer  = issuer_dict.get("organizationName", issuer_dict.get("commonName", ""))
                info.subject = subject_dict.get("commonName", domain)

                # Expiry
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    try:
                        expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    except ValueError:
                        # Fallback for timezone abbreviations that strptime doesn't handle
                        try:
                            expire_dt = datetime.strptime(expire_str.rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y")
                        except ValueError:
                            expire_dt = None
                    if expire_dt:
                        info.expires = expire_dt.strftime("%Y-%m-%d")
                        now = datetime.now(timezone.utc).replace(tzinfo=None)
                        info.days_remaining = (expire_dt - now).days
                # Expiry warnings
                if info.days_remaining <= 0:
                    info.vulnerabilities.append("Certificate is EXPIRED")
                    info.valid = False
                elif info.days_remaining <= 14:
                    info.vulnerabilities.append(f"Certificate expires in {info.days_remaining} days (CRITICAL)")
                elif info.days_remaining <= 30:
                    info.vulnerabilities.append(f"Certificate expires in {info.days_remaining} days (WARNING)")

    except BlockedDestinationError:
        info.valid = False
        info.vulnerabilities.append("Domain resolves to a non-public address; the TLS check was not performed")
    except ssl.SSLCertVerificationError as e:
        info.valid = False
        info.vulnerabilities.append(f"Certificate validation failed: {str(e)[:100]}")
    except ssl.SSLError as e:
        # Handshake failed under TLS 1.2+; the server may only speak a deprecated protocol.
        info.valid = False
        legacy = _legacy_tls_version(address, domain, port) if address else None
        if legacy:
            info.protocol = legacy
            info.vulnerabilities.append(
                f"Server only supports {LEGACY_TLS_LABELS[legacy]}; modern browsers refuse to connect"
            )
        else:
            info.vulnerabilities.append(f"TLS handshake failed: {str(e)[:100]}")
    except ConnectionRefusedError:
        info.valid = False
        info.vulnerabilities.append("HTTPS not available on port 443")
    except socket.gaierror:
        info.valid = False
        info.vulnerabilities.append("DNS resolution failed — domain may not exist or is unreachable")
    except socket.timeout:
        info.valid = False
        info.vulnerabilities.append("SSL connection timed out — server may be slow or blocking")
    except OSError as e:
        info.valid = False
        info.vulnerabilities.append(f"Network error: {str(e)[:100]}")
    except Exception as e:
        info.valid = False
        info.vulnerabilities.append(f"SSL check failed: {str(e)[:100]}")

    # A server that negotiates TLS 1.2+ may still accept deprecated protocols.
    if info.protocol in ("TLSv1.2", "TLSv1.3") and address:
        legacy = _legacy_tls_version(address, domain, port)
        if legacy:
            info.vulnerabilities.append(
                f"Server still accepts {LEGACY_TLS_LABELS[legacy]} (deprecated TLS 1.0/1.1)"
            )

    info.grade = _grade(info)
    return info


def _grade(info: SSLInfo) -> str:
    """Grade protocol and certificate health independently; the worst issue wins."""
    if not info.protocol:
        return "N/A"
    if not info.valid or info.protocol in LEGACY_TLS_LABELS:
        return "F" if info.days_remaining <= 0 and info.expires else "D"
    accepts_legacy = any("deprecated TLS 1.0/1.1" in v for v in info.vulnerabilities)
    if accepts_legacy or info.days_remaining <= 14:
        return "C"
    if info.days_remaining <= 30:
        return "B"
    return "A"
