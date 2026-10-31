from privacy_posture import headless


def test_chrome_bin_env_override(tmp_path, monkeypatch):
    fake = tmp_path / "mybrowser"
    fake.write_text("")
    monkeypatch.setenv("CHROME_BIN", str(fake))
    assert headless._chromium_bin() == str(fake)


def test_chrome_bin_ignores_missing_override(monkeypatch):
    monkeypatch.setenv("CHROME_BIN", "/nonexistent/browser")
    # Falls back to auto-detection; must return a str (path or empty), never raise.
    assert isinstance(headless._chromium_bin(), str)
