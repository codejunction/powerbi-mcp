"""
Error handling utilities for type-safe MCP server operations.
"""
from typing import Any, Optional
from pydantic import BaseModel, Field


class McpError(BaseModel):
    """Standardized error response for MCP operations."""
    error_type: str = Field(description="Type of error (validation, authentication, authorization, etc.)")
    message: str = Field(description="Human-readable error message")
    details: Optional[dict[str, Any]] = Field(default=None, description="Additional error details")
    is_retriable: bool = Field(default=False, description="Whether the error is retriable")


class ValidationError(McpError):
    """Validation error for invalid input."""
    error_type: str = "validation_error"
    is_retriable: bool = False


class AuthenticationError(McpError):
    """Authentication error for failed authentication."""
    error_type: str = "authentication_error"
    is_retriable: bool = False


class AuthorizationError(McpError):
    """Authorization error for insufficient permissions."""
    error_type: str = "authorization_error"
    is_retriable: bool = False


class NotFoundError(McpError):
    """Not found error for missing resources."""
    error_type: str = "not_found_error"
    is_retriable: bool = False


class RateLimitError(McpError):
    """Rate limit error for too many requests."""
    error_type: str = "rate_limit_error"
    is_retriable: bool = True


class ServiceUnavailableError(McpError):
    """Service unavailable error for temporary outages."""
    error_type: str = "service_unavailable_error"
    is_retriable: bool = True


def handle_error(error: Exception) -> McpError:
    """Convert exceptions to standardized MCP errors."""
    if isinstance(error, ValueError):
        return ValidationError(message=str(error))
    elif isinstance(error, PermissionError):
        return AuthorizationError(message=str(error))
    elif "not found" in str(error).lower():
        return NotFoundError(message=str(error))
    elif "rate limit" in str(error).lower():
        return RateLimitError(message=str(error))
    elif "unavailable" in str(error).lower():
        return ServiceUnavailableError(message=str(error))
    else:
        return McpError(
            error_type="internal_error",
            message=str(error),
            is_retriable=False
        )
