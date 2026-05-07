import sqlite3

DB_NAME = "cybermind.db"

def connect_db():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

conn = connect_db()
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    severity TEXT,
    details TEXT
)
""")

conn.commit()

def create_user(username, password):

    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password)
        )

        conn.commit()
        return True

    except:
        return False

def validate_user(username, password):

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    return cursor.fetchone()

def save_alert(ip, severity, details):

    cursor.execute(
        """
        INSERT INTO alerts (ip, severity, details)
        VALUES (?, ?, ?)
        """,
        (ip, severity, details)
    )

    conn.commit()

def get_alerts():

    cursor.execute(
        "SELECT * FROM alerts"
    )

    return cursor.fetchall()

def alert_exists(ip, details):

    cursor.execute(
        """
        SELECT * FROM alerts
        WHERE ip=? AND details=?
        """,
        (ip, details)
    )

    return cursor.fetchone()