from pydantic import BaseModel

from typing import Dict


class APIResponse(BaseModel):

    status: str

    timestamp: str

    analysis_result: Dict