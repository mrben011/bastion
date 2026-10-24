"""Rate limiter shared by every API instance, backed by the database.

Serverless functions each have their own memory, so an in-process counter would never reach its limit.
This uses a fixed window per key. A client can briefly send up to twice the limit across a window
boundary, which is acceptable for login throttling. Call db.commit() is handled here so a counted
attempt survives even when the request later fails.
"""
import random
import time

from sqlalchemy import text
from sqlalchemy.orm import Session


def allow(db: Session, key: str, limit: int, window_seconds: int = 60) -> bool:
    bucket = int(time.time() // window_seconds)
    hits = db.execute(
        text(
            "INSERT INTO rate_limits (key, bucket, hits) VALUES (:k, :b, 1) "
            "ON CONFLICT (key, bucket) DO UPDATE SET hits = rate_limits.hits + 1 RETURNING hits"
        ),
        {"k": key[:200], "b": bucket},
    ).scalar_one()
    if random.random() < 0.01:  # occasional cleanup keeps the table small
        db.execute(text("DELETE FROM rate_limits WHERE bucket < :old"), {"old": bucket - 120})
    db.commit()
    return hits <= limit
