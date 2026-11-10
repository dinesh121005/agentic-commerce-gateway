"""
Persistent Catalog Service Layer backed by database (SQLite/PostgreSQL).

Provides shared, reusable catalog query, CRUD, lookup, and inventory functions
used across FastAPI HTTP routers, Merchant AI, and MCP servers.
"""
import time
from typing import List, Optional, Tuple
from app.catalog.data import PRODUCTS
from app.catalog.models import CreateProductRequest, Product, UpdateProductRequest
from app.db import get_db_connection
from app.exceptions import ProductNotFoundError

_catalog_initialized = False


def _ensure_catalog_db_initialized() -> None:
    """
    Ensures database tables catalog_products, product_relationships,
    and recommendations exist and are seeded from initial seed data.
    """
    global _catalog_initialized
    if _catalog_initialized:
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Catalog Products Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS catalog_products (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                merchant_id TEXT NOT NULL,
                price REAL NOT NULL,
                price_paise INTEGER,
                stock INTEGER NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cat_status ON catalog_products (status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cat_category ON catalog_products (category);")

        # 2. Product Relationships Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS product_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_product_id TEXT NOT NULL,
                target_product_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL DEFAULT 'COMPLEMENTARY',
                created_at REAL NOT NULL,
                UNIQUE(source_product_id, target_product_id)
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON product_relationships (source_product_id);")

        # 3. Recommendations State & Idempotency Table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recommendations (
                recommendation_id TEXT PRIMARY KEY,
                primary_product_id TEXT NOT NULL,
                addon_product_id TEXT NOT NULL,
                customer_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'GENERATED',
                primary_transaction_id TEXT,
                addon_transaction_id TEXT,
                logical_order_group_id TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rec_status ON recommendations (status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rec_primary_tx ON recommendations (primary_transaction_id);")

        conn.commit()

        # Safe migration: ensure all expected columns exist on catalog_products
        cursor.execute("SELECT * FROM catalog_products LIMIT 0;")
        existing_cols = [desc[0].lower() for desc in (cursor.description or [])]

        if "merchant_id" not in existing_cols:
            try:
                cursor.execute("ALTER TABLE catalog_products ADD COLUMN merchant_id TEXT NOT NULL DEFAULT 'MERCH_ELEC';")
                conn.commit()
            except Exception:
                pass

        if "status" not in existing_cols:
            try:
                cursor.execute("ALTER TABLE catalog_products ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';")
                conn.commit()
            except Exception:
                pass

        now_ts = time.time()
        if "created_at" not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE catalog_products ADD COLUMN created_at REAL NOT NULL DEFAULT {now_ts};")
                conn.commit()
            except Exception:
                pass

        if "updated_at" not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE catalog_products ADD COLUMN updated_at REAL NOT NULL DEFAULT {now_ts};")
                conn.commit()
            except Exception:
                pass

        if "price_paise" not in existing_cols:
            try:
                cursor.execute("ALTER TABLE catalog_products ADD COLUMN price_paise INTEGER;")
                conn.commit()
            except Exception:
                pass

        # Always ensure all catalog products from seed data exist (ON CONFLICT DO NOTHING preserves edited products)
        from decimal import Decimal, ROUND_HALF_UP
        for p in PRODUCTS:
            p_status = "ACTIVE" if p.stock > 0 else "OUT_OF_STOCK"
            p_paise = int((Decimal(str(p.price)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            cursor.execute(
                """
                INSERT INTO catalog_products (
                    id, name, category, merchant_id, price, price_paise, stock, description, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO NOTHING;
                """,
                (p.id, p.name, p.category, p.merchant_id, p.price, p_paise, p.stock, p.description, p_status, now_ts, now_ts),
            )
        conn.commit()

        # Backfill any remaining null price_paise (e.g. from existing unpopulated rows)
        try:
            cursor.execute("SELECT id, price FROM catalog_products WHERE price_paise IS NULL;")
            rows = cursor.fetchall()
            for r_id, r_price in rows:
                p_paise = int((Decimal(str(r_price)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
                cursor.execute("UPDATE catalog_products SET price_paise = ? WHERE id = ?;", (p_paise, r_id))
            conn.commit()
        except Exception:
            pass

        # Seed default affinity graph into product_relationships if empty
        cursor.execute("SELECT COUNT(*) FROM product_relationships;")
        rel_count = cursor.fetchone()[0]
        if rel_count == 0:
            initial_affinity = {
                "KB001": ["HK001", "HK002"],
                "MN001": ["KB001", "HK001"],
                "HK001": ["FD007", "HK002", "AP001"],
                "HK002": ["HK001", "AP001"],
                "HK005": ["FD007", "HK001"],
                "HK006": ["FD016", "FD021"],
                "FD001": ["FD002", "FD020"],
                "FD002": ["FD001", "FD008"],
                "FD007": ["HK001", "FD003", "FD011"],
                "FD011": ["FD005", "FD007"],
                "FD016": ["FD021", "FD012"],
                "FD021": ["FD016", "HK006"],
                "AP001": ["HK002", "HK001"],
            }
            for src, targets in initial_affinity.items():
                for tgt in targets:
                    cursor.execute(
                        """
                        INSERT INTO product_relationships (
                            source_product_id, target_product_id, relationship_type, created_at
                        ) VALUES (?, ?, 'COMPLEMENTARY', ?)
                        ON CONFLICT(source_product_id, target_product_id) DO NOTHING;
                        """,
                        (src, tgt, now_ts),
                    )
            conn.commit()

    _catalog_initialized = True


def row_to_product(row: tuple) -> Product:
    """Converts a database tuple row into a Pydantic Product model."""
    return Product(
        id=str(row[0]),
        name=str(row[1]),
        category=str(row[2]),
        merchant_id=str(row[3]) if len(row) > 3 and row[3] else "MERCH_ELEC",
        price=float(row[4]),
        stock=int(row[5]),
        description=str(row[6]) if len(row) > 6 and row[6] else "",
        status=str(row[7]) if len(row) > 7 and row[7] else "ACTIVE",
    )


def search_products(
    query: Optional[str] = None,
    category: Optional[str] = None,
    max_price: Optional[float] = None,
    include_all_statuses: bool = False,
) -> List[Product]:
    """
    Search and filter products from the persistent database catalog.
    Supports multi-word search, category filtering, max price limit, and status check.
    """
    _ensure_catalog_db_initialized()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        sql = (
            "SELECT id, name, category, merchant_id, price, stock, description, status "
            "FROM catalog_products "
        )
        conditions = []
        params = []

        if not include_all_statuses:
            conditions.append("status != 'ARCHIVED'")

        if category is not None and category.strip():
            conditions.append("LOWER(category) = ?")
            params.append(category.strip().lower())

        if max_price is not None:
            conditions.append("price <= ?")
            params.append(float(max_price))

        if conditions:
            sql += "WHERE " + " AND ".join(conditions) + " "

        sql += "ORDER BY id ASC;"
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()

    all_products = [row_to_product(r) for r in rows]

    if query is not None and query.strip():
        search_term = query.strip().lower()
        query_words = [w for w in search_term.split() if w]
        filtered = []
        for p in all_products:
            name_lower = p.name.lower()
            desc_lower = (p.description or "").lower()
            cat_lower = p.category.lower()
            if (
                search_term in name_lower
                or search_term in desc_lower
                or all(w in f"{name_lower} {cat_lower} {desc_lower}" for w in query_words)
            ):
                filtered.append(p)

        if filtered:
            return filtered

        # Fallback 1: Filter common conversational filler terms
        filler_words = {
            "yes", "search", "for", "the", "a", "an", "buy", "find", "show",
            "me", "get", "please", "want", "looking", "i", "can", "you", "need"
        }
        meaningful_words = [w for w in query_words if w not in filler_words and len(w) > 1]

        if meaningful_words:
            for p in all_products:
                name_lower = p.name.lower()
                desc_lower = (p.description or "").lower()
                cat_lower = p.category.lower()
                target_str = f"{name_lower} {cat_lower} {desc_lower}"
                if all(w in target_str for w in meaningful_words):
                    filtered.append(p)

        if filtered:
            return filtered

        # Fallback 2: Match any meaningful word if all-word match still returned 0
        if meaningful_words:
            for p in all_products:
                name_lower = p.name.lower()
                desc_lower = (p.description or "").lower()
                cat_lower = p.category.lower()
                target_str = f"{name_lower} {cat_lower} {desc_lower}"
                if any(w in target_str for w in meaningful_words if len(w) > 2):
                    filtered.append(p)

        return filtered

    return all_products


def get_product(product_id: str) -> Product:
    """
    Retrieve a single product by its ID from the database catalog.
    Raises ProductNotFoundError if not found or ARCHIVED.
    """
    _ensure_catalog_db_initialized()
    clean_id = product_id.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, category, merchant_id, price, stock, description, status
            FROM catalog_products
            WHERE id = ? AND status != 'ARCHIVED';
            """,
            (clean_id,),
        )
        row = cursor.fetchone()

    if row is None:
        raise ProductNotFoundError(clean_id)
    return row_to_product(row)


def decrement_stock(product_id: str, quantity: int = 1) -> bool:
    """
    Safely decrements persistent inventory stock for a product upon purchase confirmation.
    Automatically updates status to OUT_OF_STOCK if stock reaches 0.
    """
    _ensure_catalog_db_initialized()
    clean_id = product_id.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT stock FROM catalog_products WHERE id = ?;", (clean_id,))
        row = cursor.fetchone()
        if not row:
            return False
        current_stock = int(row[0])
        if current_stock < quantity:
            return False

        new_stock = current_stock - quantity
        new_status = "OUT_OF_STOCK" if new_stock == 0 else "ACTIVE"
        now = time.time()
        cursor.execute(
            """
            UPDATE catalog_products
            SET stock = ?, status = ?, updated_at = ?
            WHERE id = ?;
            """,
            (new_stock, new_status, now, clean_id),
        )
        conn.commit()
        return True


def restore_stock(product_id: str, quantity: int = 1) -> None:
    """
    Restores persistent inventory stock for a product if an order is cancelled or rolled back.
    """
    _ensure_catalog_db_initialized()
    clean_id = product_id.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT stock, status FROM catalog_products WHERE id = ?;", (clean_id,))
        row = cursor.fetchone()
        if row:
            current_stock = int(row[0])
            new_stock = current_stock + quantity
            new_status = "ACTIVE" if row[1] == "OUT_OF_STOCK" else row[1]
            now = time.time()
            cursor.execute(
                """
                UPDATE catalog_products
                SET stock = ?, status = ?, updated_at = ?
                WHERE id = ?;
                """,
                (new_stock, new_status, now, clean_id),
            )
            conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# Store Catalog Persistent Admin CRUD Functions (Section 11 Requirement)
# ══════════════════════════════════════════════════════════════════════════════

def list_products_admin() -> List[Product]:
    """Retrieves all catalog products including inactive/out-of-stock items for Admin management."""
    _ensure_catalog_db_initialized()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, category, merchant_id, price, stock, description, status
            FROM catalog_products
            ORDER BY created_at DESC, id ASC;
            """
        )
        rows = cursor.fetchall()
    return [row_to_product(r) for r in rows]


def create_product(req: CreateProductRequest) -> Product:
    """Creates a new catalog product in persistent database storage."""
    _ensure_catalog_db_initialized()
    clean_id = req.id.strip().upper()
    now = time.time()
    p_status = req.status.upper() if req.status else ("ACTIVE" if req.stock > 0 else "OUT_OF_STOCK")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM catalog_products WHERE id = ?;", (clean_id,))
        if cursor.fetchone() is not None:
            raise ValueError(f"Product ID '{clean_id}' already exists in catalog.")

        p_paise = int((Decimal(str(req.price)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        cursor.execute(
            """
            INSERT INTO catalog_products (
                id, name, category, merchant_id, price, price_paise, stock, description, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                clean_id,
                req.name.strip(),
                req.category.strip().lower(),
                req.merchant_id.strip(),
                float(req.price),
                p_paise,
                int(req.stock),
                req.description.strip(),
                p_status,
                now,
                now,
            ),
        )
        conn.commit()

    return get_product(clean_id)


def update_product(product_id: str, req: UpdateProductRequest) -> Product:
    """Updates fields of an existing catalog product in persistent database storage."""
    _ensure_catalog_db_initialized()
    clean_id = product_id.strip()
    existing = get_product(clean_id)

    name = req.name.strip() if req.name is not None else existing.name
    category = req.category.strip().lower() if req.category is not None else existing.category
    price = float(req.price) if req.price is not None else existing.price
    stock = int(req.stock) if req.stock is not None else existing.stock
    description = req.description.strip() if req.description is not None else existing.description
    status = req.status.upper() if req.status is not None else existing.status

    if req.stock is not None and req.stock == 0 and status == "ACTIVE":
        status = "OUT_OF_STOCK"

    now = time.time()
    p_paise = int((Decimal(str(price)) * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE catalog_products
            SET name = ?, category = ?, price = ?, price_paise = ?, stock = ?, description = ?, status = ?, updated_at = ?
            WHERE id = ?;
            """,
            (name, category, price, p_paise, stock, description, status, now, clean_id),
        )
        conn.commit()

    return get_product(clean_id)


def archive_product(product_id: str) -> bool:
    """
    Soft-deletes a product by setting status = 'ARCHIVED'.
    Preserves historical integrity for audit_records referencing this product ID.
    """
    _ensure_catalog_db_initialized()
    clean_id = product_id.strip()
    now = time.time()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE catalog_products
            SET status = 'ARCHIVED', updated_at = ?
            WHERE id = ?;
            """,
            (now, clean_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def get_product_relationships(source_product_id: str) -> List[str]:
    """
    Queries persistent product_relationships table for complementary add-on product IDs linked to source.
    """
    _ensure_catalog_db_initialized()
    clean_id = source_product_id.strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT target_product_id
            FROM product_relationships
            WHERE source_product_id = ?
            ORDER BY id ASC;
            """,
            (clean_id,),
        )
        rows = cursor.fetchall()
    return [r[0] for r in rows]


def add_product_relationship(source_product_id: str, target_product_id: str, relationship_type: str = "COMPLEMENTARY") -> bool:
    """
    Adds a persistent relationship between a source product and target add-on product.
    """
    _ensure_catalog_db_initialized()
    now = time.time()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO product_relationships (source_product_id, target_product_id, relationship_type, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_product_id, target_product_id) DO NOTHING;
            """,
            (source_product_id.strip(), target_product_id.strip(), relationship_type, now),
        )
        conn.commit()
        return cursor.rowcount > 0

