"""Giao diện chung cho mọi giao thức truyền tệp. Muốn thêm giao thức mới: kế thừa lớp này."""
from __future__ import annotations
from abc import ABC, abstractmethod


class TransferError(Exception):
    pass


class TransferBackend(ABC):
    name: str = "base"

    @abstractmethod
    def upload(self, local_path: str, remote_path: str) -> None: ...

    @abstractmethod
    def download(self, remote_path: str, local_path: str) -> None: ...

    def delete(self, remote_path: str) -> None:
        """Xóa file trên máy chủ (dùng để dọn file đo của benchmark). Lớp con nên ghi đè."""
        raise TransferError(f"{self.name} chưa hỗ trợ xóa file từ xa")
