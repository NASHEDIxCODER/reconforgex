"""
Custom exceptions for the ReconForgeX framework.

Every module-specific exception inherits from ``ReconForgeXError`` so that
callers can catch a single base type when appropriate.
"""


class ReconForgeXError(Exception):
    """Base exception for all ReconForgeX framework errors."""


class ConfigurationError(ReconForgeXError):
    """Raised when the configuration is invalid or missing."""


class ToolExecutionError(ReconForgeXError):
    """Raised when an external tool fails or is not found."""


class PipelineError(ReconForgeXError):
    """Raised when the execution pipeline encounters a fatal condition."""


class ReportError(ReconForgeXError):
    """Raised when report generation fails."""


class ValidationError(ReconForgeXError):
    """Raised when input validation fails."""


class TimeoutError(ReconForgeXError):
    """Raised when an operation exceeds the configured timeout."""
