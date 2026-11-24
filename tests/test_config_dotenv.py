import pytest

from securetransfer.config import Settings, _load_dotenv

KEYS = ["T_PLAIN", "T_HASH", "T_HASH2", "T_QUOTED", "T_SINGLE", "T_COMMENT", "T_EXPORT", "T_EMPTY",
        "T_EQ", "T_BOM", "T_KEEP", "T_NOCLOSE", "T_URL"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)
    yield
    # monkeypatch không biết os.environ.setdefault của _load_dotenv đã thêm gì nên dọn tay
    import os
    for k in KEYS:
        os.environ.pop(k, None)


def _load(tmp_path, text, newline="\n"):
    p = tmp_path / ".env"
    p.write_bytes(text.replace("\n", newline).encode("utf-8"))
    _load_dotenv(str(p))


def test_hash_inside_value_is_kept(tmp_path):
    import os
    _load(tmp_path, "T_HASH=p#ssw0rd\nT_HASH2=abc#123#xyz\nT_URL=http://h/p#frag\n")
    assert os.environ["T_HASH"] == "p#ssw0rd"
    assert os.environ["T_HASH2"] == "abc#123#xyz"
    assert os.environ["T_URL"] == "http://h/p#frag"


def test_inline_comment_is_stripped_only_after_whitespace(tmp_path):
    import os
    _load(tmp_path, "T_COMMENT=value   # ghi chú\nT_PLAIN=abc\n")
    assert os.environ["T_COMMENT"] == "value"
    assert os.environ["T_PLAIN"] == "abc"


def test_quoted_values_keep_hash_and_spaces(tmp_path):
    import os
    _load(tmp_path, 'T_QUOTED="a #b  c"   # chú thích\nT_SINGLE=\'x # y\'\n')
    assert os.environ["T_QUOTED"] == "a #b  c"
    assert os.environ["T_SINGLE"] == "x # y"


def test_unterminated_quote_does_not_crash(tmp_path):
    import os
    _load(tmp_path, 'T_NOCLOSE="abc\n')
    assert os.environ["T_NOCLOSE"] == '"abc'


def test_comment_lines_blank_lines_and_export(tmp_path):
    import os
    _load(tmp_path, "# T_PLAIN=khong-duoc-nap\n\n   \nexport T_EXPORT=ok\nT_EMPTY=\n")
    assert "T_PLAIN" not in os.environ
    assert os.environ["T_EXPORT"] == "ok"
    assert os.environ["T_EMPTY"] == ""


def test_value_may_contain_equals(tmp_path):
    import os
    _load(tmp_path, "T_EQ=abc==\n")
    assert os.environ["T_EQ"] == "abc=="


def test_crlf_and_bom(tmp_path):
    import os
    p = tmp_path / ".env"
    p.write_bytes(b"\xef\xbb\xbfT_BOM=1\r\nT_PLAIN=2\r\n")
    _load_dotenv(str(p))
    assert os.environ["T_BOM"] == "1"                     # khóa đầu file không bị dính BOM
    assert os.environ["T_PLAIN"] == "2"


def test_existing_environment_wins(tmp_path, monkeypatch):
    import os
    monkeypatch.setenv("T_KEEP", "from-env")
    _load(tmp_path, "T_KEEP=from-file\n")
    assert os.environ["T_KEEP"] == "from-env"


def test_password_with_hash_reaches_settings(tmp_path, monkeypatch):
    for k in ("ST_FTPS_PASSWORD", "ST_ALLOW_LEGACY_ENC"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ST_FTPS_PASSWORD=Mat#Khau#123\nST_ALLOW_LEGACY_ENC=true\n", encoding="utf-8")
    try:
        s = Settings.from_env()
        assert s.ftps_password == "Mat#Khau#123"
        assert s.allow_legacy_enc is True
    finally:
        import os
        os.environ.pop("ST_FTPS_PASSWORD", None)
        os.environ.pop("ST_ALLOW_LEGACY_ENC", None)
