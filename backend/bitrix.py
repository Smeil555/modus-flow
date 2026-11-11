"""Interface for a future Bitrix24 adapter. No network calls are made by this module."""
from typing import Protocol

class BitrixClient(Protocol):
    def create_task(self, *, title:str, description:str, responsible_id:str, idempotency_key:str) -> dict: ...
    def get_task(self, external_id:str) -> dict: ...

class BitrixNotConfigured(RuntimeError):
    pass

def bitrix_client() -> BitrixClient:
    raise BitrixNotConfigured('Интеграция Битрикс24 не настроена')
