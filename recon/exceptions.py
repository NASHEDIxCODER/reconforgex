"""
Custom exceptions for the recon framework.

Every module-specific exception inherits from ``ReconError`` so that
callers can catch a single base type when appropriate.
"""


class ReconError(Exception):
    """Base exception for all recon framework errors."""


class ConfigurationError(ReconError):
    """Raised when the configuration is invalid or missing."""


class ToolExecutionError(ReconError):
    """Raised when an external tool fails or is not found."""


class PipelineError(ReconError):
    """Raised when the execution pipeline encounters a fatal condition."""


class ReportError(ReconError):
    """Raised when report generation fails."""


class ValidationError(ReconError):
    """Raised when input validation fails."""


class TimeoutError(ReconError):
    """Raised when an operation exceeds the configured timeout."""