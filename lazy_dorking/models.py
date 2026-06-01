from pydantic import BaseModel


class ScanRequest(BaseModel):
    domain: str
    platforms: list[str] = []


class BACScanRequest(BaseModel):
    domain: str
    services: list[str]
    include_dorking: bool = False


class CredScanRequest(BaseModel):
    domain: str
    categories: list[str] = []
    active_bruteforce: bool = False


class ResultStatusUpdate(BaseModel):
    status: str
