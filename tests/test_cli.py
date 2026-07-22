"""Tests for recon.cli argument parsing."""

import pytest
from recon.cli import build_parser


class TestCliParser:
    """Tests for the CLI argument parser."""

    def test_parser_created(self) -> None:
        parser = build_parser()
        assert parser is not None
        assert parser.description is not None
        assert "reconnaissance" in parser.description.lower()

    def test_parse_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.domain == "example.com"
        assert args.output is None
        assert args.port_scan is False
        assert args.vuln_scan is False
        assert args.verbose is False

    def test_parse_all_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "-d", "test.com",
            "-o", "/tmp/output",
            "--port-scan",
            "--vuln-scan",
            "--verbose",
        ])
        assert args.domain == "test.com"
        assert args.output == "/tmp/output"
        assert args.port_scan is True
        assert args.vuln_scan is True
        assert args.verbose is True

    def test_parse_config_positional(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["my_config.yaml"])
        assert args.config == "my_config.yaml"
        assert args.domain is None

    def test_parse_no_args(self) -> None:
        """Should parse without arguments (domain validation happens later)."""
        parser = build_parser()
        args = parser.parse_args([])
        assert args.domain is None
        assert args.config is None

    def test_version(self) -> None:
        """Calling --version should call sys.exit(0)."""
        import sys

        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0