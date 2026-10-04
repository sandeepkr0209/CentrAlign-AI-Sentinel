class ToolError(Exception):
    """A tool failed in an expected, reportable way."""
    def __init__(self, code: str, message: str, retryable: bool = False, details: dict | None = None):
        super().__init__(message)
        self.code, self.retryable, self.details = code, retryable, details or {}


class TransientToolError(ToolError):
    def __init__(self, message: str = "Temporary failure, retrying may succeed."):
        super().__init__("TEMPORARY_FAILURE", message, retryable=True)
