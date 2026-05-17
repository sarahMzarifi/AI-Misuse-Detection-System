from pydantic import BaseModel

from typing import Dict


class APIResponse(BaseModel):

    status: str

    timestamp: str

    analysis_result: Dict

class ErrorResponse(BaseModel):

    status: str

    timestamp: str

    message: str

    details: str