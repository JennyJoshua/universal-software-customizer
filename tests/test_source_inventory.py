from customizer.source_inventory import create_source_review


def test_source_review_lists_excluded_and_included_paths_without_execution(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app").mkdir()
    (source / "app" / "main.py").write_text("print('ok')", encoding="utf-8")
    (source / ".env").write_text("SECRET=not-reported", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("[remote]", encoding="utf-8")
    report = create_source_review(source)
    assert report["execution_performed"] is False
    assert report["human_review_required"] is True
    assert report["scanned_file_count"] == 1
    assert report["entries"] == [
        {"path": ".env", "status": "excluded", "reason": "sensitive_file"},
        {"path": ".git", "status": "excluded", "reason": "sensitive_directory"},
        {"path": "app/main.py", "status": "included", "size_bytes": 11},
    ]
    assert "not-reported" not in str(report)


def test_source_review_reports_secret_rule_without_value(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "settings.txt").write_text("token=sk-proj-" + "A" * 24, encoding="utf-8")
    report = create_source_review(source)
    assert report["potential_secret_finding_count"] == 1
    assert report["entries"][0]["status"] == "review_required"
    assert "openai_api_key" in report["entries"][0]["rules"]
    assert "A" * 24 not in str(report)


def test_source_review_is_deterministic_and_bounds_reported_entries(tmp_path, monkeypatch):
    import customizer.source_inventory as inventory
    source = tmp_path / "source"
    source.mkdir()
    for name in ("z.txt", "a.txt", "m.txt"):
        (source / name).write_text(name, encoding="utf-8")
    first, second = create_source_review(source), create_source_review(source)
    assert first["entries"] == second["entries"]
    monkeypatch.setattr(inventory, "_MAX_REPORTED_ENTRIES", 2)
    bounded = create_source_review(source)
    assert len(bounded["entries"]) == 2
    assert bounded["entries_truncated"] is True
