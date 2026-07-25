"""Tests for reconforgex.cli argument parsing."""

import pytest

from reconforgex.cli import build_parser


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
        assert args.verbose is False
        assert args.workers is None

    def test_parse_all_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "-d", "test.com",
            "-o", "/tmp/output",
            "-w", "100",
            "--verbose",
        ])
        assert args.domain == "test.com"
        assert args.output == "/tmp/output"
        assert args.workers == 100
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
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0

    def test_list_modules(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--list-modules"])
        assert args.list_modules is True

    def test_report_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-d", "x.com", "--no-html", "--no-json"])
        assert args.no_html is True
        assert args.no_json is True
        assert args.no_markdown is False
