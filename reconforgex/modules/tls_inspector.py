"""
TLS Inspector Module.

Inspects TLS/SSL certificate details, protocol versions, and cipher
suites by establishing connections to targets. Built entirely in Python.
"""

import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional, Tuple

from reconforgex.logger import get_logger
from reconforgex.modules.base import (
    BaseModule,
    ModuleConfiguration,
    ModuleHealth,
    ModuleMetadata,
    ModuleStatus,
)

log = get_logger()


@dataclass
class TLSResult:
    """TLS inspection result for a single target."""
    host: str
    port: int
    tls_version: Optional[str]
    certificate_issuer: Optional[str]
    certificate_subject: Optional[str]
    certificate_serial: Optional[str]
    certificate_fingerprint: Optional[str]
    valid_from: Optional[str]
    valid_until: Optional[str]
    days_remaining: int
    is_expired: bool
    is_self_signed: bool
    san_list: List[str]
    cipher_suite: Optional[str]
    supports_http2: bool
    error: Optional[str] = None


# Common TLS versions and their SSL context mappings
TLS_VERSIONS = {
    "TLS 1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None,
    "TLS 1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None,
    "TLS 1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None,
    "TLS 1.3": ssl.PROTOCOL_TLS,  # TLS 1.3 is default in modern Python
}

COMMON_PORTS = [443, 8443, 465, 993, 995, 2525, 587, 2083, 2087, 2096, 8443]


class TLSInspector(BaseModule):
    """TLS Inspector Module.

    Inspects TLS/SSL certificates, protocol versions, and security
    configurations of target hosts. Detects expired certificates,
    self-signed certificates, and weak TLS versions.
    """

    def __init__(self, config: Optional[ModuleConfiguration] = None):
        super().__init__(config)
        self._timeout = config.extra.get("timeout", 10) if config else 10

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="TLS Inspector",
            description="Inspect TLS/SSL certificates, protocol versions, and security configurations",
            version="1.0.0",
            author="ReconForgeX",
            tags=["tls", "ssl", "certificate", "security", "crypto"],
        )

    def health(self) -> ModuleHealth:
        return ModuleHealth(
            healthy=True,
            message="TLS Inspector module operational",
            last_check=time.time(),
        )

    def _get_certificate_info(self, host: str, port: int) -> Optional[TLSResult]:
        """Connect to a host and retrieve TLS certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    if not cert:
                        return TLSResult(
                            host=host,
                            port=port,
                            tls_version=tls_version,
                            certificate_issuer=None,
                            certificate_subject=None,
                            certificate_serial=None,
                            certificate_fingerprint=None,
                            valid_from=None,
                            valid_until=None,
                            days_remaining=0,
                            is_expired=False,
                            is_self_signed=False,
                            san_list=[],
                            cipher_suite=cipher[0] if cipher else None,
                            supports_http2=tls_version == "TLSv1.3",
                            error="No certificate returned",
                        )

                    # Extract certificate details
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    valid_from_str = cert.get("notBefore", "")
                    valid_until_str = cert.get("notAfter", "")

                    # Parse dates
                    valid_from = None
                    valid_until = None
                    days_remaining = 0
                    is_expired = True

                    if valid_until_str:
                        try:
                            valid_until = datetime.strptime(
                                valid_until_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            days_remaining = (valid_until - datetime.now()).days
                            is_expired = days_remaining < 0
                        except ValueError:
                            pass

                    if valid_from_str:
                        try:
                            valid_from = datetime.strptime(
                                valid_from_str, "%b %d %H:%M:%S %Y %Z"
                            )
                        except ValueError:
                            pass

                    # Extract SANs
                    san_list: List[str] = []
                    for ext in cert.get("subjectAltName", ()):
                        if ext[0] == "DNS":
                            san_list.append(ext[1])

                    # Check if self-signed
                    issuer_str = issuer.get("organizationName", "")
                    subject_str = subject.get("organizationName", "")
                    is_self_signed = issuer_str == subject_str or not issuer_str

                    return TLSResult(
                        host=host,
                        port=port,
                        tls_version=tls_version,
                        certificate_issuer=issuer.get("organizationName", str(issuer)),
                        certificate_subject=subject.get("commonName", str(subject)),
                        certificate_serial=cert.get("serialNumber"),
                        certificate_fingerprint=None,  # Not available via stdlib
                        valid_from=valid_from.isoformat() if valid_from else None,
                        valid_until=valid_until.isoformat() if valid_until else None,
                        days_remaining=days_remaining,
                        is_expired=is_expired,
                        is_self_signed=is_self_signed,
                        san_list=san_list,
                        cipher_suite=cipher[0] if cipher else None,
                        supports_http2=tls_version == "TLSv1.3",
                    )

        except socket.timeout:
            return TLSResult(
                host=host, port=port, tls_version=None,
                certificate_issuer=None, certificate_subject=None,
                certificate_serial=None, certificate_fingerprint=None,
                valid_from=None, valid_until=None, days_remaining=0,
                is_expired=False, is_self_signed=False, san_list=[],
                cipher_suite=None, supports_http2=False,
                error=f"Connection timed out after {self._timeout}s",
            )
        except ConnectionRefusedError:
            return TLSResult(
                host=host, port=port, tls_version=None,
                certificate_issuer=None, certificate_subject=None,
                certificate_serial=None, certificate_fingerprint=None,
                valid_from=None, valid_until=None, days_remaining=0,
                is_expired=False, is_self_signed=False, san_list=[],
                cipher_suite=None, supports_http2=False,
                error="Connection refused",
            )
        except ssl.SSLError as exc:
            return TLSResult(
                host=host, port=port, tls_version=None,
                certificate_issuer=None, certificate_subject=None,
                certificate_serial=None, certificate_fingerprint=None,
                valid_from=None, valid_until=None, days_remaining=0,
                is_expired=False, is_self_signed=False, san_list=[],
                cipher_suite=None, supports_http2=False,
                error=f"SSL error: {exc}",
            )
        except Exception as exc:
            return TLSResult(
                host=host, port=port, tls_version=None,
                certificate_issuer=None, certificate_subject=None,
                certificate_serial=None, certificate_fingerprint=None,
                valid_from=None, valid_until=None, days_remaining=0,
                is_expired=False, is_self_signed=False, san_list=[],
                cipher_suite=None, supports_http2=False,
                error=str(exc),
            )

    async def run(self, target: str, **kwargs: Any) -> List[TLSResult]:
        """Run TLS inspection against the target.

        Parameters
        ----------
        target:
            Hostname or IP to inspect.
        **kwargs:
            - ports: List of ports to check (default: [443, 8443])
            - hosts: Optional list of host:port strings

        Returns
        -------
        List[TLSResult]
            List of TLS inspection results.
        """
        self.reset()
        self.stats.status = ModuleStatus.RUNNING
        self.stats.start_time = time.time()
        results: List[TLSResult] = []

        hosts_to_check: List[Tuple[str, int]] = []
        hosts = kwargs.get("hosts", [])
        if hosts:
            for host_entry in hosts:
                if ":" in host_entry:
                    h, p = host_entry.rsplit(":", 1)
                    try:
                        hosts_to_check.append((h, int(p)))
                    except ValueError:
                        hosts_to_check.append((host_entry, 443))
                else:
                    hosts_to_check.append((host_entry, 443))
        else:
            ports = kwargs.get("ports", [443, 8443])
            for port in ports:
                hosts_to_check.append((target, port))

        try:
            for host, port in hosts_to_check:
                result = self._get_certificate_info(host, port)
                results.append(result)
                self.stats.items_found += 1

        except Exception as exc:
            self._record_error(str(exc))
        finally:
            self.stats.status = ModuleStatus.COMPLETED
            self.stats.end_time = time.time()
            self.stats.items_processed = len(results)

        return results
