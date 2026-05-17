from fastapi import FastAPI
from pydantic import (
    BaseModel,
    Field,
    field_validator
)
from datetime import datetime
from services.analysis_service import (
    analyze_prompt
)
from reporting.report_generator import (
    generate_report
)
from utils.logger import (
    save_log
)
from api.schemas.response_models import (
    APIResponse,
    ErrorResponse
)

#  FASTAPI APPLICATION

app = FastAPI(

    title="AI Misuse Detection System API",

    description=(

        "Cybersecurity backend API for "
        "detecting sensitive data exposure, "
        "suspicious intent patterns, "
        "authentication bypass attempts, "
        "and potential AI misuse scenarios."

    ),

    version="1.0.0"
)

# REQUEST MODEL

class PromptRequest(BaseModel):

    prompt: str = Field(

        ...,

        min_length=3,

        max_length=1000,

        description=(
            "Prompt submitted for "
            "cybersecurity analysis"
        )
    )

    @field_validator("prompt")

    def validate_prompt(cls, value):

        cleaned_prompt = value.strip()

        if not cleaned_prompt:

            raise ValueError(
                "Prompt cannot contain only whitespace"
            )

        return cleaned_prompt


# HEALTH CHECK ENDPOINT

@app.get(

    "/",

    tags=["System"],

    summary="Health Check Endpoint",

    description=(
        "Checks whether the API "
        "service is running properly."
    )
)

def home():

    return {
        "message": "API is running"
    }


# ANALYZE ENDPOINT

@app.post(

    "/analyze",

    tags=["Cybersecurity Analysis"],

    summary="Analyze Prompt For AI Misuse",

    description=(

        "Analyzes prompts for "
        "sensitive data exposure, "
        "authentication bypass attempts, "
        "system manipulation intent, "
        "and suspicious AI misuse behavior."

    )

)

def analyze(request: PromptRequest):

    try:

        # CYBERSECURITY ANALYSIS
        analysis_result = analyze_prompt(
            request.prompt
        )

        # GENERATE FORENSIC REPORT
        forensic_report = generate_report(
            analysis_result
        )

        # SAVE FORENSIC LOG
        save_log(
            forensic_report
        )

        # STANDARDIZED SUCCESS RESPONSE
        return {

            "status": "success",

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "analysis_result": analysis_result

        }

    except Exception as error:

        # STANDARDIZED ERROR RESPONSE
        return {

            "status": "error",

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "message": "Analysis failed",

            "details": str(error)

        }