import logging
import os
from dotenv import load_dotenv

# Load .env into the process environment before any SDK clients are instantiated.
# override=False: real environment variables always win over .env values.
load_dotenv(override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth import verify_admin_key

from app.admin.router import router as admin_router
from app.agent.router import router as agent_router
from app.audit import audit_router
from app.catalog.router import router as catalog_router
from app.mcp.server import mount_remote_mcp, remote_mcp_lifespan
from app.merchant_agent import merchant_agent_router
from app.oauth.router import router as oauth_router
from app.payment.router import router as payment_router
from app.signing import signing_router
from app.merchant.router import router as merchant_router

app = FastAPI(
    title="Agentic Commerce Gateway",
    description="Merchant-side gateway enabling AI shopping agents to transact under bounded, auditable policy mandates.",
    version="1.0.0",
    lifespan=remote_mcp_lifespan,
)

class McpNormalizeMiddleware:
    """
    Normalizes /mcp requests:
    1. Prevents 307 Temporary Redirect for /mcp without trailing slash by rewriting path to /mcp/.
    2. Ensures Accept header includes text/event-stream so standard HTTP clients (like ChatGPT)
       receive JSON-RPC responses without 406 Not Acceptable errors.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            raw_path = scope.get("path", "")
            if raw_path == "/mcp" or raw_path == "/mcp/":
                scope = dict(scope)
                scope["path"] = "/mcp/"
                headers = dict(scope.get("headers", []))
                accept = headers.get(b"accept", b"")
                if b"text/event-stream" not in accept:
                    new_headers = []
                    found_accept = False
                    for k, v in scope.get("headers", []):
                        if k.lower() == b"accept":
                            found_accept = True
                            new_val = v + b", text/event-stream" if v else b"application/json, text/event-stream"
                            new_headers.append((k, new_val))
                        else:
                            new_headers.append((k, v))
                    if not found_accept:
                        new_headers.append((b"accept", b"application/json, text/event-stream"))
                    scope["headers"] = new_headers
        await self.app(scope, receive, send)


# Enable CORS for ChatGPT and web MCP clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(McpNormalizeMiddleware)

# Mount static files directory if it exists
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Mount REST, OAuth, and Merchant Agent routers
app.include_router(catalog_router)
app.include_router(agent_router)
app.include_router(audit_router)
app.include_router(admin_router)
app.include_router(oauth_router)
app.include_router(merchant_agent_router)
app.include_router(payment_router)
app.include_router(signing_router)
app.include_router(merchant_router)

# Mount remote Streamable HTTP MCP server at /mcp
mount_remote_mcp(app, path="/mcp")


@app.get("/admin/dashboard", tags=["admin"], summary="Admin Web Dashboard UI")
def get_admin_dashboard():
    """Serves the interactive Admin Web Dashboard HTML application."""
    html_path = os.path.join(static_dir, "admin", "index.html")
    return FileResponse(
        html_path,
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/checkout", tags=["payment"], summary="User Self-Checkout UI")
def get_checkout_page():
    """Serves the standalone Razorpay self-checkout page."""
    html_path = os.path.join(static_dir, "checkout", "index.html")
    return FileResponse(html_path)


@app.get("/admin", tags=["admin"], summary="Admin Web Dashboard Redirect")
def redirect_to_dashboard():
    """Redirects /admin to the Admin Web Dashboard."""
    return RedirectResponse(url="/admin/dashboard")


@app.get("/health", tags=["system"], summary="Health check endpoint")
def health_check() -> dict:
    """
    Returns the operational status of the gateway services.
    """
    return {
        "status": "healthy",
        "service": "gateway",
        "version": "1.0.0"
    }


@app.get("/api/analytics/growth-benchmark", tags=["analytics"], summary="Track 01 Empirical Growth Telemetry")
def get_growth_benchmark() -> dict:
    """
    Returns transparent empirical AOV uplift metrics and per-transaction telemetry for Track 01.
    """
    import json
    benchmark_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks", "aov_benchmark_results.json")
    if os.path.exists(benchmark_path):
        try:
            with open(benchmark_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    from scripts.benchmark_aov import run_benchmark
    return run_benchmark()


@app.get("/api/analytics/recommendations", tags=["analytics"], summary="Real-time Recommendation & AOV Telemetry")
def get_recommendation_analytics_endpoint() -> dict:
    """
    Returns dynamic recommendation lifecycle telemetry, exact Logical Order AOV uplift,
    and attach rate computed strictly from confirmed transaction/payment records.
    """
    from app.audit.store import audit_store
    return audit_store.get_recommendation_analytics()


@app.get(
    "/debug-search",
    tags=["system"],
    summary="Production Search Diagnostic Endpoint",
    dependencies=[Depends(verify_admin_key)],
)
def debug_search_endpoint(query: str = "keyboard") -> dict:
    """
    Diagnostic endpoint to inspect database connection target, catalog table row count,
    product statuses, and search_products execution traceback.
    Guarded strictly by Admin API Key authentication (VULN-08 remediation).
    """
    import traceback
    from app.db import get_db_connection
    from app.catalog.service import search_products, _ensure_catalog_db_initialized

    raw_url = os.environ.get("DATABASE_URL", "gateway.db")
    db_type = "postgresql" if ("postgres://" in raw_url or "postgresql://" in raw_url) else "sqlite"

    result = {
        "db_type": db_type,
        "raw_url_prefix": raw_url[:15] if raw_url else "None",
        "product_count": 0,
        "kb001_product": None,
        "sample_products": [],
        "search_results": [],
        "error": None,
        "traceback": None,
    }

    try:
        _ensure_catalog_db_initialized()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM catalog_products;")
            result["product_count"] = cursor.fetchone()[0]

            cursor.execute("SELECT id, name, category, price, stock, status FROM catalog_products WHERE id = 'KB001';")
            kb_row = cursor.fetchone()
            if kb_row:
                result["kb001_product"] = {
                    "id": kb_row[0],
                    "name": kb_row[1],
                    "category": kb_row[2],
                    "price": kb_row[3],
                    "stock": kb_row[4],
                    "status": kb_row[5],
                }

            cursor.execute("SELECT id, name, category, price, stock, status FROM catalog_products LIMIT 5;")
            result["sample_products"] = [
                {"id": r[0], "name": r[1], "category": r[2], "price": r[3], "stock": r[4], "status": r[5]}
                for r in cursor.fetchall()
            ]

        products = search_products(query=query)
        result["search_results"] = [p.model_dump() for p in products]

    except Exception as e:
        result["error"] = str(e)
        is_prod = os.environ.get("ENVIRONMENT", "development").lower() == "production"
        result["traceback"] = None if is_prod else traceback.format_exc()

    return result



