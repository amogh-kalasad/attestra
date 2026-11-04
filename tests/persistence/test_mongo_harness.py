"""The fresh_db fixture always runs on a throwaway attestra_test_* MongoDB database."""
from __future__ import annotations

import os


def test_fresh_db_is_mongo_test_db(fresh_db):
    import attestra.config as cfg
    from attestra.persistence.mongo.client import get_db

    assert cfg.PERSISTENCE_BACKEND == "mongo"
    assert os.environ["ATTESTRA_PERSISTENCE"] == "mongo"
    name = get_db().name
    assert name.startswith("attestra_test_") and name != "attestra"
