"""
Domain exceptions for the Agentic Commerce Gateway.

Provides cleanly separated domain error types so business and service layers
remain transport-agnostic and do not leak HTTP status codes directly into services or MCP handlers.
"""


class GatewayError(Exception):
    """Base exception for domain errors in the gateway."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ProductNotFoundError(GatewayError):
    """Raised when a requested product cannot be found in the catalog."""
    def __init__(self, product_id: str):
        super().__init__(f"Product with id '{product_id}' not found")
        self.product_id = product_id


class MandateNotFoundError(GatewayError):
    """Raised when a customer mandate cannot be found."""
    def __init__(self, customer_id: str):
        super().__init__(f"Mandate for customer '{customer_id}' not found")
        self.customer_id = customer_id


class InsufficientStockError(GatewayError):
    """Raised when requested purchase quantity exceeds available product inventory."""
    def __init__(self, product_id: str, requested: int, available: int):
        super().__init__(
            f"Requested quantity {requested} exceeds available inventory {available} for product '{product_id}'"
        )
        self.product_id = product_id
        self.requested = requested
        self.available = available


class InvalidPurchaseError(GatewayError):
    """Raised when purchase parameters fail domain validation (e.g. quantity < 1)."""
    pass


class StalePriceError(GatewayError):
    """Raised when a product's live catalog price differs from the proposed/confirmed price."""
    def __init__(self, product_id: str, proposed_amount: float, live_amount: float):
        super().__init__(
            f"Catalog price has changed since purchase proposal for product '{product_id}' "
            f"(proposed total: ₹{proposed_amount:.2f}, live total: ₹{live_amount:.2f}). "
            f"A new purchase proposal must be requested and authorized."
        )
        self.product_id = product_id
        self.proposed_amount = proposed_amount
        self.live_amount = live_amount
