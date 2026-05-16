from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from services.analysis_service import analyze_prompt
from api.schemas.response_models import APIResponse


# FASTAPI APPLICATION

app = FastAPI()


# REQUEST MODEL

class PromptRequest(BaseModel):

    prompt: str


# HEALTH CHECK ENDPOINT

@app.get("/")
def home():

    return {

        "message": "API is running"

    }


# ANALYZE ENDPOINT

@app.post(

    "/analyze",

    response_model=APIResponse

)
def analyze(request: PromptRequest):

    # CYBERSECURITY ANALYSIS

    analysis_result = analyze_prompt(
        request.prompt
    )

    # STANDARDIZED API RESPONSE

    return {

        "status": "success",

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "analysis_result": analysis_result

    }