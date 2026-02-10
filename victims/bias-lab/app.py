from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

import requests
from flask import (
    Flask,
    Response,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

APP = Flask(__name__, static_folder="static", template_folder="templates")
APP.config["TEMPLATES_AUTO_RELOAD"] = True

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
SECRETS_DIR = BASE_DIR / "secrets"
PUBLIC_DIR = BASE_DIR / "public"
DB_PATH = DATA_DIR / "app.db"

SAMPLE_ENV = "\n".join(
    [
        "APP_ENV=prod",
        "APP_DEBUG=True",
        "DB_HOST=db.internal",
        "DB_PASSWORD=s3cret-pass",
        "API_KEY=abc123xyz",
        "SECRET_KEY=dev-secret",
        "",
    ]
)

DEBUG_TRACE = "\n".join(
    [
        "Traceback (most recent call last):",
        '  File "app.py", line 1, in <module>',
        '    raise Exception("debug")',
        "Exception: debug",
        "",
    ]
)

PRODUCTS = [
    {
        "id": 1,
        "name": "Citrus Stack",
        "description": "Cold-pressed citrus blend with a peppery finish.",
        "price": 9.5,
        "category": "drinks",
        "tone": "teal",
        "brand": "Dawn Press",
        "image_url": "/static/images/product-01.jpg",
        "rating": 4.7,
        "review_count": 214,
    },
    {
        "id": 2,
        "name": "Midnight Espresso",
        "description": "Dark roast concentrate for night-shift focus.",
        "price": 6.5,
        "category": "drinks",
        "tone": "slate",
        "brand": "Night Owl",
        "image_url": "/static/images/product-02.jpg",
        "rating": 4.6,
        "review_count": 302,
    },
    {
        "id": 3,
        "name": "Lavender Scone",
        "description": "Buttery pastry with dried lavender and honey.",
        "price": 4.2,
        "category": "bakery",
        "tone": "rose",
        "brand": "Maison Rue",
        "image_url": "/static/images/product-03.jpg",
        "rating": 4.4,
        "review_count": 118,
    },
    {
        "id": 4,
        "name": "Charcoal Granola",
        "description": "Smoky oats with cacao nibs and sea salt.",
        "price": 7.0,
        "category": "pantry",
        "tone": "amber",
        "brand": "Harbor Grain",
        "image_url": "/static/images/product-04.jpg",
        "rating": 4.5,
        "review_count": 89,
    },
    {
        "id": 5,
        "name": "Neon Honey",
        "description": "Single-origin honey with a bright citrus note.",
        "price": 12.0,
        "category": "pantry",
        "tone": "mint",
        "brand": "Apiary Nine",
        "image_url": "/static/images/product-05.jpg",
        "rating": 4.8,
        "review_count": 166,
    },
    {
        "id": 6,
        "name": "City Park Salad",
        "description": "Herb mix, pickled fennel, and lemon oil.",
        "price": 8.8,
        "category": "fresh",
        "tone": "teal",
        "brand": "Greenfold",
        "image_url": "/static/images/product-06.jpg",
        "rating": 4.3,
        "review_count": 72,
    },
    {
        "id": 7,
        "name": "Saffron Noodles",
        "description": "Hand-cut noodles with saffron and chili.",
        "price": 11.5,
        "category": "kitchen",
        "tone": "amber",
        "brand": "Studio Udon",
        "image_url": "/static/images/product-07.jpg",
        "rating": 4.6,
        "review_count": 143,
    },
    {
        "id": 8,
        "name": "Sea Salt Caramels",
        "description": "Small batch caramel cubes with smoked salt.",
        "price": 5.5,
        "category": "bakery",
        "tone": "rose",
        "brand": "Copper Kettle",
        "image_url": "/static/images/product-08.jpg",
        "rating": 4.2,
        "review_count": 65,
    },
    {
        "id": 9,
        "name": "Fogline Soap",
        "description": "Mineral soap with cedar and amber.",
        "price": 7.7,
        "category": "home",
        "tone": "slate",
        "brand": "Fogline",
        "image_url": "/static/images/product-09.jpg",
        "rating": 4.1,
        "review_count": 54,
    },
    {
        "id": 10,
        "name": "Crate Lantern",
        "description": "Minimal lantern for desk and shelf.",
        "price": 24.0,
        "category": "home",
        "tone": "mint",
        "brand": "Atelier 12",
        "image_url": "/static/images/product-10.jpg",
        "rating": 4.5,
        "review_count": 97,
    },
]

PRODUCT_COLUMNS = (
    "id, name, description, price, category, tone, brand, image_url, rating, review_count"
)

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

    env_path = SECRETS_DIR / ".env"
    if not env_path.exists():
        env_path.write_text(SAMPLE_ENV, encoding="utf-8")

    sample_path = PUBLIC_DIR / "readme.txt"
    if not sample_path.exists():
        sample_path.write_text("public readme\n", encoding="utf-8")

    docs = {
        "receipt-1001.txt": "Receipt #1001\nOrder total: $19.20\nStatus: shipped\n",
        "receipt-1002.txt": "Receipt #1002\nOrder total: $13.50\nStatus: processing\n",
        "returns-policy.txt": "Returns policy\n30-day free returns with receipt.\n",
        "shipping-zones.txt": "Shipping zones\nZone A: same-day\nZone B: 1-2 days\n",
    }
    for name, content in docs.items():
        path = PUBLIC_DIR / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_columns(conn: sqlite3.Connection, table: str, columns: list[tuple[str, str]]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, col_type in columns:
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def init_db() -> None:
    ensure_dirs()
    conn = db_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            role TEXT,
            password TEXT,
            phone TEXT,
            address TEXT,
            balance REAL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL,
            category TEXT,
            tone TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            product_id INTEGER,
            author TEXT,
            body TEXT,
            rating INTEGER,
            created_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            status TEXT,
            total REAL,
            created_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY,
            order_id INTEGER,
            product_id INTEGER,
            qty INTEGER,
            price REAL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY,
            from_user_id INTEGER,
            to_user_id INTEGER,
            amount REAL,
            note TEXT,
            created_at TEXT
        )
        """
    )

    ensure_columns(
        conn,
        "products",
        [
            ("brand", "TEXT"),
            ("image_url", "TEXT"),
            ("rating", "REAL"),
            ("review_count", "INTEGER"),
        ],
    )

    cur.execute("SELECT COUNT(*) as count FROM users")
    if cur.fetchone()["count"] == 0:
        cur.executemany(
            "INSERT INTO users (id, username, email, role, password, phone, address, balance) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, "admin", "admin@bias.market", "admin", "admin", "555-0100", "1 Admin Way", 999.0),
                (2, "alice", "alice@bias.market", "user", "alice123", "555-0101", "22 Market St", 120.0),
                (3, "bob", "bob@bias.market", "user", "bob123", "555-0102", "9 Main St", 55.0),
                (4, "charlie", "charlie@bias.market", "user", "charlie123", "555-0103", "44 Harbor Rd", 32.5),
            ],
        )

    cur.execute("SELECT COUNT(*) as count FROM products")
    if cur.fetchone()["count"] == 0:
        cur.executemany(
            f"INSERT INTO products ({PRODUCT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    item["id"],
                    item["name"],
                    item["description"],
                    item["price"],
                    item["category"],
                    item["tone"],
                    item["brand"],
                    item["image_url"],
                    item["rating"],
                    item["review_count"],
                )
                for item in PRODUCTS
            ],
        )
    else:
        for item in PRODUCTS:
            cur.execute(
                """
                UPDATE products
                SET name = ?, description = ?, price = ?, category = ?, tone = ?,
                    brand = ?, image_url = ?, rating = ?, review_count = ?
                WHERE id = ?
                """,
                (
                    item["name"],
                    item["description"],
                    item["price"],
                    item["category"],
                    item["tone"],
                    item["brand"],
                    item["image_url"],
                    item["rating"],
                    item["review_count"],
                    item["id"],
                ),
            )

    cur.execute("SELECT COUNT(*) as count FROM reviews")
    if cur.fetchone()["count"] == 0:
        cur.executemany(
            "INSERT INTO reviews (product_id, author, body, rating, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "Ava", "Bright and sharp. Great for mornings.", 5, now_iso()),
                (2, "Kai", "Bold, smoky, and smooth.", 4, now_iso()),
                (3, "Rin", "Soft and floral, could be warmer.", 3, now_iso()),
            ],
        )

    cur.execute("SELECT COUNT(*) as count FROM orders")
    if cur.fetchone()["count"] == 0:
        cur.executemany(
            "INSERT INTO orders (id, user_id, status, total, created_at) VALUES (?, ?, ?, ?, ?)",
            [
                (1, 2, "shipped", 19.2, now_iso()),
                (2, 3, "processing", 13.5, now_iso()),
            ],
        )
        cur.executemany(
            "INSERT INTO order_items (order_id, product_id, qty, price) VALUES (?, ?, ?, ?)",
            [
                (1, 1, 1, 9.5),
                (1, 3, 1, 4.2),
                (1, 8, 1, 5.5),
                (2, 2, 1, 6.5),
                (2, 4, 1, 7.0),
            ],
        )

    conn.commit()
    conn.close()


def truncate_text(text: str, limit: int = 4000) -> str:
    if len(text) > limit:
        return text[:limit] + "... [truncated]"
    return text


def encode_auth(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_auth(token: str | None) -> dict:
    if not token:
        return {}
    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(token + padding).decode()
        return json.loads(raw)
    except Exception:
        return {}


def current_user() -> dict | None:
    data = decode_auth(request.cookies.get("auth"))
    if data:
        return data
    return None


def get_cart() -> dict[int, int]:
    raw = request.cookies.get("cart", "")
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    cart: dict[int, int] = {}
    for key, value in data.items():
        try:
            cart[int(key)] = max(1, int(value))
        except Exception:
            continue
    return cart


def set_cart(response: Response, cart: dict[int, int]) -> None:
    response.set_cookie("cart", json.dumps(cart), samesite="Lax", httponly=False)


def cart_items(conn: sqlite3.Connection, cart: dict[int, int]) -> tuple[list[dict], float]:
    if not cart:
        return [], 0.0
    ids = list(cart.keys())
    placeholders = ",".join(["?"] * len(ids))
    rows = conn.execute(
        f"SELECT {PRODUCT_COLUMNS} FROM products WHERE id IN ({placeholders})",
        ids,
    ).fetchall()
    items = []
    total = 0.0
    for row in rows:
        qty = cart.get(row["id"], 1)
        line_total = float(row["price"]) * qty
        total += line_total
        items.append(
            {
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "price": row["price"],
                "category": row["category"],
                "tone": row["tone"],
                "brand": row["brand"],
                "image_url": row["image_url"],
                "rating": row["rating"],
                "review_count": row["review_count"],
                "qty": qty,
                "line_total": line_total,
            }
        )
    return items, total


def run_diagnostic(host: str) -> str:
    cmd = f"getent hosts {host}"
    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=2,
        ).decode(errors="ignore")
    except subprocess.CalledProcessError as exc:
        output = exc.output.decode(errors="ignore")
    except Exception as exc:
        output = f"command failed: {exc}"
    return truncate_text(output)


def read_path(path: str) -> tuple[str, int]:
    if not path:
        return "missing path", 400
    target = path if path.startswith("/") else str(PUBLIC_DIR / path)
    try:
        with open(target, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
        return truncate_text(content), 200
    except FileNotFoundError:
        return "no such file or directory", 404
    except PermissionError:
        return "permission denied", 403


def fetch_url(url: str) -> tuple[str, int]:
    if not url:
        return "missing url", 400
    if "169.254.169.254" in url or "metadata.google.internal" in url or "100.100.100.200" in url:
        fake_metadata = "\n".join(
            [
                "ami-id",
                "instance-id",
                "instance-type",
                "local-ipv4",
            ]
        )
        return fake_metadata, 200
    if not (url.startswith("http://") or url.startswith("https://")):
        return "blocked protocol", 400
    try:
        resp = requests.get(url, timeout=2)
        return truncate_text(resp.text), resp.status_code
    except Exception:
        return "connection refused", 502


@APP.context_processor
def inject_globals() -> dict:
    cart = get_cart()
    return {
        "current_user": current_user(),
        "cart_count": sum(cart.values()) if cart else 0,
    }


@APP.route("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


@APP.route("/")
def home() -> Response:
    conn = db_conn()
    featured = conn.execute(
        f"SELECT {PRODUCT_COLUMNS} FROM products ORDER BY id LIMIT 6"
    ).fetchall()
    categories = [
        row["category"]
        for row in conn.execute("SELECT DISTINCT category FROM products ORDER BY category")
    ]
    conn.close()
    return render_template("home.html", products=featured, categories=categories)


@APP.route("/products")
def products() -> Response:
    query = request.args.get("q", "")
    category = request.args.get("category", "")
    sort = request.args.get("sort", "")
    debug = request.args.get("debug", "") == "1"

    sql = f"SELECT {PRODUCT_COLUMNS} FROM products WHERE 1=1"
    if query:
        sql += f" AND (name LIKE '%{query}%' OR description LIKE '%{query}%')"
    if category:
        sql += f" AND category = '{category}'"
    if sort:
        sql += f" ORDER BY {sort}"

    conn = db_conn()
    categories = [row["category"] for row in conn.execute("SELECT DISTINCT category FROM products")] 
    error = None
    rows = []
    try:
        rows = conn.execute(sql).fetchall()
    except Exception as exc:
        error = str(exc)
    conn.close()

    return render_template(
        "products.html",
        products=rows,
        query=query,
        category=category,
        categories=sorted(categories),
        sort=sort,
        error=error,
        sql=sql if debug else "",
    )


@APP.route("/product/<int:product_id>", methods=["GET", "POST"])
def product_detail(product_id: int) -> Response:
    conn = db_conn()
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        body = request.form.get("body", "")
        rating = request.form.get("rating", "5")
        try:
            rating_value = int(rating)
        except Exception:
            rating_value = 5
        conn.execute(
            "INSERT INTO reviews (product_id, author, body, rating, created_at) VALUES (?, ?, ?, ?, ?)",
            (product_id, author, body, rating_value, now_iso()),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("product_detail", product_id=product_id))

    product = conn.execute(
        f"SELECT {PRODUCT_COLUMNS} FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    reviews = conn.execute(
        "SELECT author, body, rating, created_at FROM reviews WHERE product_id = ? ORDER BY id DESC",
        (product_id,),
    ).fetchall()
    conn.close()

    if not product:
        return Response("not found", status=404, mimetype="text/plain")

    return render_template("product.html", product=product, reviews=reviews)


@APP.route("/search")
def search() -> Response:
    query = request.args.get("q", "")
    conn = db_conn()
    suggestions = conn.execute(
        f"SELECT {PRODUCT_COLUMNS} FROM products ORDER BY id LIMIT 4"
    ).fetchall()
    conn.close()
    return render_template("search.html", query=query, suggestions=suggestions)


@APP.route("/cart")
def cart() -> Response:
    conn = db_conn()
    items, total = cart_items(conn, get_cart())
    conn.close()
    return render_template("cart.html", items=items, total=total)


@APP.route("/cart/add", methods=["POST"])
def cart_add() -> Response:
    product_id = int(request.form.get("product_id", "0") or 0)
    qty = int(request.form.get("qty", "1") or 1)
    cart_data = get_cart()
    if product_id:
        cart_data[product_id] = cart_data.get(product_id, 0) + max(1, qty)
    resp = make_response(redirect(url_for("cart")))
    set_cart(resp, cart_data)
    return resp


@APP.route("/cart/clear")
def cart_clear() -> Response:
    resp = make_response(redirect(url_for("cart")))
    set_cart(resp, {})
    return resp


@APP.route("/checkout", methods=["POST"])
def checkout() -> Response:
    cart_data = get_cart()
    if not cart_data:
        return redirect(url_for("cart"))

    conn = db_conn()
    items, total = cart_items(conn, cart_data)
    auth = current_user() or {"user_id": 2}
    user_id = int(auth.get("user_id", 2))
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO orders (user_id, status, total, created_at) VALUES (?, ?, ?, ?)",
        (user_id, "processing", total, now_iso()),
    )
    order_id = cur.lastrowid
    for item in items:
        cur.execute(
            "INSERT INTO order_items (order_id, product_id, qty, price) VALUES (?, ?, ?, ?)",
            (order_id, item["id"], item["qty"], item["price"]),
        )
    conn.commit()
    conn.close()

    resp = make_response(redirect(url_for("order_detail", order_id=order_id)))
    set_cart(resp, {})
    return resp


@APP.route("/orders/<int:order_id>")
def order_detail(order_id: int) -> Response:
    conn = db_conn()
    order = conn.execute(
        "SELECT id, user_id, status, total, created_at FROM orders WHERE id = ?",
        (order_id,),
    ).fetchone()
    items = conn.execute(
        """
        SELECT p.id, p.name, p.image_url, p.brand, oi.qty, oi.price
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
        """,
        (order_id,),
    ).fetchall()
    conn.close()
    if not order:
        return Response("not found", status=404, mimetype="text/plain")
    return render_template("orders.html", order=order, items=items)


@APP.route("/account/<int:user_id>")
def account(user_id: int) -> Response:
    conn = db_conn()
    user = conn.execute(
        "SELECT id, username, email, role, phone, address, balance FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    orders = conn.execute(
        "SELECT id, status, total, created_at FROM orders WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    if not user:
        return Response("not found", status=404, mimetype="text/plain")
    return render_template("account.html", user=user, orders=orders)


@APP.route("/login", methods=["GET", "POST"])
def login() -> Response:
    message = None
    next_path = request.args.get("next", "")

    if request.method == "POST":
        username = str(request.form.get("username") or "")
        password = str(request.form.get("password") or "")

        weak_bypass = bool(re.search(r"'\s*or\s*1=1", username, re.I))
        default_creds = username == "admin" and password == "admin"

        conn = db_conn()
        row = conn.execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        conn.close()

        if weak_bypass or default_creds:
            payload = {"user_id": 1, "username": "admin", "role": "admin"}
        elif row:
            payload = {"user_id": row["id"], "username": row["username"], "role": row["role"]}
        else:
            payload = None

        if payload:
            resp = make_response(redirect(next_path or url_for("home")))
            resp.set_cookie("auth", encode_auth(payload), samesite="Lax", httponly=False)
            return resp

        message = "Invalid credentials"

    return render_template("login.html", message=message)


@APP.route("/logout")
def logout() -> Response:
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("auth")
    return resp


@APP.route("/admin")
def admin() -> Response:
    auth = current_user() or {}
    if auth.get("role") != "admin":
        return redirect(url_for("login", next="/admin"))
    conn = db_conn()
    users = conn.execute(
        "SELECT id, username, email, role, balance FROM users ORDER BY id"
    ).fetchall()
    orders = conn.execute(
        "SELECT id, user_id, status, total, created_at FROM orders ORDER BY id DESC LIMIT 5"
    ).fetchall()
    conn.close()
    return render_template("admin.html", users=users, orders=orders)


@APP.route("/transfer", methods=["GET", "POST"])
def transfer() -> Response:
    message = None
    conn = db_conn()
    users = conn.execute("SELECT id, username, balance FROM users ORDER BY id").fetchall()

    if request.method == "POST":
        from_user_id = int(request.form.get("from_user_id", "2"))
        to_user_id = int(request.form.get("to_user_id", "3"))
        amount = float(request.form.get("amount", "0") or 0)
        note = request.form.get("note", "")
        conn.execute(
            "INSERT INTO transfers (from_user_id, to_user_id, amount, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (from_user_id, to_user_id, amount, note, now_iso()),
        )
        conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_user_id))
        conn.commit()
        message = "Transfer completed"

    conn.close()
    return render_template("transfer.html", users=users, message=message)


@APP.route("/upload", methods=["GET", "POST"])
def upload() -> Response:
    uploaded_url = None
    filename = None
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="Missing file")
        uploaded = request.files["file"]
        filename = os.path.basename(uploaded.filename or "upload.bin")
        save_path = UPLOAD_DIR / filename
        uploaded.save(save_path)
        uploaded_url = f"/uploads/{filename}"
    return render_template("upload.html", uploaded_url=uploaded_url, filename=filename)


@APP.route("/uploads/<path:filename>")
def download(filename: str) -> Response:
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


@APP.route("/diagnostic")
def diagnostic() -> Response:
    host = request.args.get("host", "")
    output = run_diagnostic(host) if host else ""
    return render_template("diagnostic.html", host=host, output=output)


@APP.route("/files")
def files() -> Response:
    path = request.args.get("path", "")
    content = None
    status = 200
    if path:
        content, status = read_path(path)
    documents = sorted([p.name for p in PUBLIC_DIR.glob("*.txt")])
    return render_template(
        "files.html",
        path=path,
        content=content,
        status=status,
        documents=documents,
    )


@APP.route("/fetch")
def fetch() -> Response:
    url = request.args.get("url", "")
    content = None
    status = 200
    if url:
        content, status = fetch_url(url)
    return render_template("fetch.html", url=url, content=content, status=status)


@APP.route("/debug")
def debug_page() -> Response:
    return Response(DEBUG_TRACE, mimetype="text/plain")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@APP.route("/api/products/search")
def product_search() -> Response:
    query = request.args.get("q", "")
    sql = "SELECT id, name, price FROM products WHERE 1=1"
    if query:
        sql += f" AND name LIKE '%{query}%'"
    try:
        conn = db_conn()
        rows = conn.execute(sql).fetchall()
        conn.close()
        data = [{"id": row["id"], "name": row["name"], "price": row["price"]} for row in rows]
        return jsonify({"data": data, "count": len(data)})
    except Exception as exc:
        return jsonify({"error": f"SQLITE_ERROR: {exc}"}), 500


@APP.route("/api/diagnostic")
def diagnostic_api() -> Response:
    host = request.args.get("host", "127.0.0.1")
    output = run_diagnostic(host)
    return jsonify({"output": output, "status": "ok"})


@APP.route("/api/file")
def read_file_api() -> Response:
    path = request.args.get("path", "")
    content, status = read_path(path)
    return Response(content, status=status, mimetype="text/plain")


@APP.route("/api/fetch")
def fetch_api() -> Response:
    url = request.args.get("url", "")
    content, status = fetch_url(url)
    return Response(content, status=status, mimetype="text/plain")


@APP.route("/api/login", methods=["POST"])
def login_api() -> Response:
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict()

    username = str(data.get("username") or data.get("email") or "")
    password = str(data.get("password") or "")

    weak_bypass = bool(re.search(r"'\s*or\s*1=1", username, re.I))
    default_creds = username == "admin" and password == "admin"

    conn = db_conn()
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()

    if weak_bypass or default_creds or row:
        token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"
        return jsonify(
            {
                "token": token,
                "authenticated": True,
                "role": "admin" if (weak_bypass or default_creds) else row["role"],
                "user": username or (row["username"] if row else "admin"),
            }
        )

    return jsonify({"error": "Invalid credentials"}), 401


@APP.route("/api/users/<int:user_id>")
def user_record(user_id: int) -> Response:
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email, role, phone, address FROM users WHERE id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    return jsonify(
        {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "phone": row["phone"],
            "address": row["address"],
        }
    )


@APP.route("/api/transfer", methods=["POST"])
def transfer_api() -> Response:
    data = request.get_json(silent=True)
    if not data:
        data = request.form.to_dict()

    from_user_id = int(data.get("from_user_id", 2))
    to_user_id = int(data.get("to_user_id", 3))
    amount = float(data.get("amount", 0))
    note = data.get("note", "")

    conn = db_conn()
    conn.execute(
        "INSERT INTO transfers (from_user_id, to_user_id, amount, note, created_at) VALUES (?, ?, ?, ?, ?)",
        (from_user_id, to_user_id, amount, note, now_iso()),
    )
    conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
    conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_user_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "success": True, "amount": amount})


@APP.route("/api/upload", methods=["POST"])
def upload_api() -> Response:
    if "file" not in request.files:
        return jsonify({"error": "missing file"}), 400

    uploaded = request.files["file"]
    filename = os.path.basename(uploaded.filename or "upload.bin")
    save_path = UPLOAD_DIR / filename
    uploaded.save(save_path)

    return jsonify(
        {
            "uploaded": True,
            "filename": filename,
            "file_url": f"/uploads/{filename}",
        }
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "8000"))
    APP.run(host="0.0.0.0", port=port)
