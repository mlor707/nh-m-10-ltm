"""Giao diện web phải có chức năng chia sẻ link (kiểm tra nội dung index.html, không cần chạy server)."""
import os

import securetransfer

INDEX = os.path.join(os.path.dirname(securetransfer.__file__), "web", "index.html")


def _html():
    with open(INDEX, encoding="utf-8") as f:
        return f.read()


def test_share_button_and_api_calls_present():
    html = _html()
    assert 'id="shareBox"' in html
    assert '"Chia sẻ"' in html and "function openShare" in html
    assert '"/documents/" + encodeURIComponent(d.name) + "/share"' in html
    assert '"/share/" + encodeURIComponent(token)' in html and 'method: "DELETE"' in html


def test_share_ui_never_uses_innerhtml_with_server_data():
    html = _html()
    assert ".innerHTML" not in html and "insertAdjacentHTML" not in html   # dữ liệu từ server luôn đi qua h()/textContent
    assert "Tài liệu Tuyệt mật không được chia sẻ" in html
