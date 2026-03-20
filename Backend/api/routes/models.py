from pydantic import BaseModel


class HealthResponse(BaseModel):
    overall: str
    services: dict[str, str]
