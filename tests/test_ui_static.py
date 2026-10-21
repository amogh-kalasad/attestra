from fastapi.testclient import TestClient

from attestra.api import app


def test_ui_stylesheet_and_fonts_are_served_same_origin():
    c = TestClient(app)
    r = c.get("/static/attestra.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")
    assert "/static/fonts/Inter.woff2" in r.text
    f = c.get("/static/fonts/Fraunces.woff2")
    assert f.status_code == 200 and f.headers["content-type"] == "font/woff2"
    j = c.get("/static/attestra.js")
    assert j.status_code == 200
    assert j.headers["content-type"].startswith("application/javascript")
    assert "MutationObserver" in j.text


def test_static_route_only_serves_allow_listed_files():
    c = TestClient(app)
    assert c.get("/static/../ui.py").status_code == 404
    assert c.get("/static/fonts/nope.woff2").status_code == 404
