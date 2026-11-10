from typing import Optional
from pydantic import BaseModel, Field


class Product(BaseModel):
    """
    Product entity representation in the Catalog.
    Strictly typed for downstream consumption by AI shopping agents and the Policy Engine.
    """
    id: str = Field(..., description="Unique identifier for the product")
    name: str = Field(..., description="Name of the product")
    category: str = Field(..., description="Category to which the product belongs")
    merchant_id: str = Field(..., description="Identifier of the merchant supplying this product")
    price: float = Field(..., gt=0, description="Price of the product in INR (₹)")
    price_paise: Optional[int] = Field(default=None, description="Authoritative price in integer paise (₹1 = 100 paise)")
    stock: int = Field(..., ge=0, description="Available inventory stock count")
    description: str = Field(..., description="Detailed description of the product")
    status: str = Field(default="ACTIVE", description="Catalog product status (ACTIVE, OUT_OF_STOCK, INACTIVE, ARCHIVED)")


class CreateProductRequest(BaseModel):
    """Payload to create a new catalog product (Admin CRUD)."""
    id: str = Field(..., description="Unique Product ID (e.g. 'EL011')")
    name: str = Field(..., description="Product display name")
    category: str = Field(..., description="Category name")
    merchant_id: str = Field(default="MERCH_ELEC", description="Merchant ID")
    price: float = Field(..., gt=0, description="Price in INR (₹)")
    price_paise: Optional[int] = Field(default=None, description="Price in integer paise")
    stock: int = Field(..., ge=0, description="Available stock count")
    description: str = Field(default="", description="Product description")
    status: str = Field(default="ACTIVE", description="Status (ACTIVE, OUT_OF_STOCK, INACTIVE)")


class UpdateProductRequest(BaseModel):
    """Payload to update an existing catalog product (Admin CRUD)."""
    name: Optional[str] = Field(None, description="Updated name")
    category: Optional[str] = Field(None, description="Updated category")
    price: Optional[float] = Field(None, gt=0, description="Updated price in INR (₹)")
    price_paise: Optional[int] = Field(None, description="Updated price in integer paise")
    stock: Optional[int] = Field(None, ge=0, description="Updated stock count")
    description: Optional[str] = Field(None, description="Updated description")
    status: Optional[str] = Field(None, description="Updated status (ACTIVE, OUT_OF_STOCK, INACTIVE, ARCHIVED)")

