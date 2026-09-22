from io import BytesIO

from app import app


def test_upload_rejects_non_log_extension():
    client = app.test_client()
    response = client.post("/upload", data={"log_file": (BytesIO(b"not a log"), "events.csv")}, content_type="multipart/form-data")
    assert response.status_code == 302


def test_basic_auth_when_configured(monkeypatch):
    monkeypatch.setenv("SENTRYLINE_AUTH_USER", "analyst")
    monkeypatch.setenv("SENTRYLINE_AUTH_PASSWORD", "secret")
    client = app.test_client()
    assert client.get("/api/results").status_code == 401
    response = client.get("/api/results", headers={"Authorization": "Basic YW5hbHlzdDpzZWNyZXQ="})
    assert response.status_code == 200


def test_benchmark_metrics_calculation():
    from app import benchmark_metrics
    metrics = benchmark_metrics()
    assert metrics is not None
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_positive_rate"] == 0.0


def test_load_sample_and_export_csv():
    client = app.test_client()
    response = client.post("/load-sample", follow_redirects=True)
    assert response.status_code == 200
    assert b"Loaded and analyzed sample" in response.data

    csv_res = client.get("/export/csv")
    assert csv_res.status_code == 200
    assert b"Alert ID,Severity" in csv_res.data


def test_alert_triage_status_lifecycle():
    client = app.test_client()
    # Ensure sample is loaded
    client.post("/load-sample", follow_redirects=True)
    results = client.get("/api/results").get_json()
    assert len(results["alerts"]) > 0
    alert_id = results["alerts"][0]["id"]

    # Update to in_progress
    resp = client.post(f"/api/alert/{alert_id}/status", json={"status": "in_progress"})
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "in_progress"

    # Reject invalid status
    bad_resp = client.post(f"/api/alert/{alert_id}/status", json={"status": "invalid_status"})
    assert bad_resp.status_code == 400

