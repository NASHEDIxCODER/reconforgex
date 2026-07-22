"""Tests for recon.utils.validators."""

import pytest
from recon.exceptions import ValidationError
from recon.utils.validators import (
    validate_domain,
    validate_url,
    validate_hostname,
    validate_subdomain_list,
)


class TestValidateDomain:
    """Tests for validate_domain."""

    def test_valid_domain(self) -> None:
        assert validate_domain("example.com") == "example.com"
        assert validate_domain("EXAMPLE.COM") == "example.com"
        assert validate_domain("sub.domain.example.com") == "sub.domain.example.com"

    def test_invalid_domain(self) -> None:
        with pytest.raises(ValidationError):
            validate_domain("")
        with pytest.raises(ValidationError):
            validate_domain("not-a-domain")
        with pytest.raises(ValidationError):
            validate_domain("http://example.com")
        with pytest.raises(ValidationError):
            validate_domain("example .com")


class TestValidateURL:
    """Tests for validate_url."""

    def test_valid_urls(self) -> None:
        assert validate_url("http://example.com") == "http://example.com"
        assert validate_url("https://example.com/path?q=1") == "https://example.com/path?q=1"
        assert validate_url("https://sub.example.com:8080") == "https://sub.example.com:8080"

    def test_invalid_urls(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("")
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com")
        with pytest.raises(ValidationError):
            validate_url("not-a-url")


class TestValidateHostname:
    """Tests for validate_hostname."""

    def test_valid_hostnames(self) -> None:
        assert validate_hostname("example.com") == "example.com"
        assert validate_hostname("192.168.1.1") == "192.168.1.1"
        assert validate_hostname("10.0.0.1") == "10.0.0.1"

    def test_invalid_hostnames(self) -> None:
        with pytest.raises(ValidationError):
            validate_hostname("")
        with pytest.raises(ValidationError):
            validate_hostname("999.999.999.999")
        with pytest.raises(ValidationError):
            validate_hostname("not valid")


class TestValidateSubdomainList:
    """Tests for validate_subdomain_list."""

    def test_valid_list(self) -> None:
        result = validate_subdomain_list(["sub.example.com", "admin.example.com"])
        assert result == ["sub.example.com", "admin.example.com"]

    def test_mixed_list(self) -> None:
        result = validate_subdomain_list(["valid.example.com", "", "not valid", "also.valid.com"])
        assert result == ["valid.example.com", "also.valid.com"]

    def test_empty_list(self) -> None:
        assert validate_subdomain_list([]) == []