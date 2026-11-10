"""Seed data generator for the Local API Security Laboratory.

Populates initial dummy test accounts, tokens, and catalog records.
All credentials and records are fictitious placeholders for safe local testing.
"""

from .database import LabDatabase


DUMMY_USERS = [
    {
        "id": 1,
        "username": "alice",
        "password": "alice123",
        "full_name": "Alice Smith",
        "email": "alice@lab.internal",
        "role": "user",
        "is_admin": 0,
        "api_token": "tok_alice_live_99182",
    },
    {
        "id": 2,
        "username": "bob",
        "password": "bob123",
        "full_name": "Bob Jones",
        "email": "bob@lab.internal",
        "role": "user",
        "is_admin": 0,
        "api_token": "tok_bob_live_47219",
    },
    {
        "id": 3,
        "username": "admin",
        "password": "AdminSuperKey_2026!",
        "full_name": "Security Administrator",
        "email": "admin@lab.internal",
        "role": "admin",
        "is_admin": 1,
        "api_token": "tok_admin_root_master_88201",
    },
]

DUMMY_ITEMS = [
    {
        "id": 1,
        "name": "Laptop Workstation",
        "description": "Standard engineering laptop",
        "price": 1299.99,
        "owner_id": 1,
    },
    {
        "id": 2,
        "name": "Hardware Security Key",
        "description": "FIDO2 WebAuthn authentication key",
        "price": 45.00,
        "owner_id": 1,
    },
    {
        "id": 3,
        "name": "Enterprise Server Rack",
        "description": "42U data center rack enclosure",
        "price": 850.00,
        "owner_id": 3,
    },
    {
        "id": 4,
        "name": "Confidential Backup Drive",
        "description": "Internal offline archive drive",
        "price": 200.00,
        "owner_id": 3,
    },
    {
        "id": 5,
        "name": "Ergonomic Office Chair",
        "description": "Adjustable high-back desk chair",
        "price": 199.99,
        "owner_id": 2,
    },
]


DUMMY_ORDERS = [
    {
        "id": 101,
        "user_id": 1,
        "item_name": "Hardware Security Key",
        "total_amount": 45.00,
        "shipping_address": "123 Alice St, Lab City",
        "order_status": "DELIVERED",
    },
    {
        "id": 102,
        "user_id": 2,
        "item_name": "Ergonomic Office Chair",
        "total_amount": 199.99,
        "shipping_address": "456 Bob Ave, Lab City",
        "order_status": "PROCESSING",
    },
    {
        "id": 103,
        "user_id": 3,
        "item_name": "Enterprise Server Rack",
        "total_amount": 850.00,
        "shipping_address": "789 Datacenter Rd, Server City",
        "order_status": "SHIPPED",
    },
]


def seed_database(db: LabDatabase) -> None:
    """Populate lab database with dummy testing dataset."""
    conn = db.get_connection()
    with conn:
        cursor = conn.cursor()

        # Clear existing tables
        cursor.execute("DELETE FROM orders")
        cursor.execute("DELETE FROM items")
        cursor.execute("DELETE FROM users")

        for u in DUMMY_USERS:
            cursor.execute(
                """
                INSERT OR REPLACE INTO users (id, username, password, full_name, email, role, is_admin, api_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u["id"],
                    u["username"],
                    u["password"],
                    u["full_name"],
                    u["email"],
                    u["role"],
                    u["is_admin"],
                    u["api_token"],
                ),
            )

        for item in DUMMY_ITEMS:
            cursor.execute(
                """
                INSERT OR REPLACE INTO items (id, name, description, price, owner_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    item["id"],
                    item["name"],
                    item["description"],
                    item["price"],
                    item["owner_id"],
                ),
            )

        for order in DUMMY_ORDERS:
            cursor.execute(
                """
                INSERT OR REPLACE INTO orders (id, user_id, item_name, total_amount, shipping_address, order_status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    order["id"],
                    order["user_id"],
                    order["item_name"],
                    order["total_amount"],
                    order["shipping_address"],
                    order["order_status"],
                ),
            )

        # Seed initial promo coupon for business flow testing
        cursor.execute(
            """
            INSERT OR REPLACE INTO coupons (code, discount_percent, times_applied)
            VALUES (?, ?, ?)
            """,
            ("SAVE50", 50.0, 0),
        )

        # Seed initial admin audit entry
        import time as _t
        cursor.execute(
            """
            INSERT OR REPLACE INTO audit_logs (id, action, target_user_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (1, "SYSTEM_INIT", 3, "Laboratory database provisioned with initial seed state", _t.time()),
        )

