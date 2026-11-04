import pytest
from attestra.persistence.mongo import client, config as mc
def test_guard(monkeypatch):
    client.close_client()
    monkeypatch.setattr(mc, "MONGODB_DB", "attestra")
    with pytest.raises(client.LiveDatabaseInTestsError):
        client.init_mongo(apply_migrations=False)
    from attestra.persistence.mongo.adapters import _db
    with pytest.raises(client.LiveDatabaseInTestsError):
        _db()
    client.close_client()
