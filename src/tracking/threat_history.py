# -----------------------------------------
# PERSISTENT THREAT HISTORY STORAGE
# -----------------------------------------

import sqlite3
from pathlib import Path


# -----------------------------------------
# DATABASE CONFIGURATION
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIRECTORY = PROJECT_ROOT / "data"

DATABASE_PATH = DATA_DIRECTORY / "security_events.db"


# -----------------------------------------
# INITIALIZE DATABASE
# -----------------------------------------

def initialize_database():
    """
    Creates the security events database and
    required table if they do not already exist.
    """

    DATA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    with sqlite3.connect(DATABASE_PATH) as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_type TEXT NOT NULL,

                event_severity TEXT NOT NULL,

                request_id TEXT NOT NULL,

                timestamp TEXT NOT NULL,

                risk_level TEXT NOT NULL,

                threat_category TEXT NOT NULL,

                threat_family TEXT NOT NULL,

                threat_type TEXT NOT NULL,

                threat_confidence TEXT NOT NULL,

                threat_priority TEXT NOT NULL
            )
            """
        )

        connection.commit()


# -----------------------------------------
# STORE STRUCTURED SECURITY EVENT
# -----------------------------------------

def store_threat_event(
    security_event
):
    """
    Stores a structured security event
    permanently in the SQLite database.
    """

    with sqlite3.connect(DATABASE_PATH) as connection:

        connection.execute(
            """
            INSERT INTO security_events (
                event_type,
                event_severity,
                request_id,
                timestamp,
                risk_level,
                threat_category,
                threat_family,
                threat_type,
                threat_confidence,
                threat_priority
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                security_event["event_type"],
                security_event["event_severity"],
                security_event["request_id"],
                security_event["timestamp"],
                security_event["risk_level"],
                security_event["threat_category"],
                security_event["threat_family"],
                security_event["threat_type"],
                security_event["threat_confidence"],
                security_event["threat_priority"]
            )
        )

        connection.commit()


# -----------------------------------------
# RETRIEVE THREAT HISTORY
# -----------------------------------------

def get_threat_history():
    """
    Retrieves all stored security events
    in chronological insertion order.

    Returns the same dictionary structure
    previously used by the in-memory system.
    """

    with sqlite3.connect(DATABASE_PATH) as connection:

        connection.row_factory = sqlite3.Row

        cursor = connection.execute(
            """
            SELECT
                event_type,
                event_severity,
                request_id,
                timestamp,
                risk_level,
                threat_category,
                threat_family,
                threat_type,
                threat_confidence,
                threat_priority
            FROM security_events
            ORDER BY id ASC
            """
        )

        rows = cursor.fetchall()

    return [
        dict(row)
        for row in rows
    ]


# -----------------------------------------
# INITIALIZE STORAGE
# -----------------------------------------

initialize_database()