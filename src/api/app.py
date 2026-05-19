from fastapi import FastAPI

from pydantic import (
    BaseModel,
    Field,
    field_validator
)

from datetime import datetime

from middleware.request_middleware import (
    RequestMonitoringMiddleware
)

from events.security_event import (
    create_security_event
)

from tracking.request_tracker import (
    generate_request_id
)

from tracking.threat_history import (
    store_threat_event,
    get_threat_history
)

from monitoring.pattern_detector import (
    detect_repeated_high_risk_activity
)

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

# -----------------------------------------
# FASTAPI APPLICATION
# -----------------------------------------

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

# -----------------------------------------
# REGISTER MIDDLEWARE
# -----------------------------------------

app.add_middleware(
    RequestMonitoringMiddleware
)

# -----------------------------------------
# REQUEST MODEL
# -----------------------------------------

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


# -----------------------------------------
# HEALTH CHECK ENDPOINT
# -----------------------------------------

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


# -----------------------------------------
# THREAT HISTORY ENDPOINT
# -----------------------------------------

@app.get(

    "/threat-history",

    tags=["Threat Monitoring"],

    summary="Retrieve Threat History",

    description=(

        "Retrieves accumulated suspicious "
        "threat activity events stored "
        "during API analysis operations."

    )
)

def threat_history():

    return {

        "status": "success",

        "threat_history": get_threat_history()

    }


# -----------------------------------------
# ANALYZE ENDPOINT
# -----------------------------------------

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

        # -----------------------------------------
        # GENERATE REQUEST ID
        # -----------------------------------------

        request_id = generate_request_id()

        # -----------------------------------------
        # CYBERSECURITY ANALYSIS
        # -----------------------------------------

        analysis_result = analyze_prompt(
            request.prompt
        )

        # -----------------------------------------
        # STORE SIGNIFICANT THREAT EVENTS
        # -----------------------------------------

        risk_level = analysis_result[
            "risk_analysis"
        ]["risk_level"]

        if risk_level != "LOW":

            # -----------------------------------------
            # CREATE STRUCTURED SECURITY EVENT
            # -----------------------------------------

            security_event = create_security_event(

                request_id=request_id,

                risk_level=risk_level,

                intent_type=analysis_result[
                    "intent_analysis"
                ]["intent_type"],

                severity=analysis_result[
                    "intent_analysis"
                ]["severity"]

            )

            # -----------------------------------------
            # STORE STRUCTURED EVENT
            # -----------------------------------------

            store_threat_event(
                security_event
            )

        # -----------------------------------------
        # RETRIEVE THREAT HISTORY
        # -----------------------------------------

        threat_history = get_threat_history()

        # -----------------------------------------
        # DETECT SUSPICIOUS ACTIVITY PATTERNS
        # -----------------------------------------

        pattern_analysis = (
            detect_repeated_high_risk_activity(
                threat_history
            )
        )

        # -----------------------------------------
        # GENERATE FORENSIC REPORT
        # -----------------------------------------

        forensic_report = generate_report(

            analysis_result,

            request_id=request_id

        )

        # -----------------------------------------
        # SAVE FORENSIC LOG
        # -----------------------------------------

        save_log(
            forensic_report
        )

        # -----------------------------------------
        # STANDARDIZED SUCCESS RESPONSE
        # -----------------------------------------

        return {

            "status": "success",

            "request_id": request_id,

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "analysis_result":
            analysis_result,

            "pattern_analysis":
            pattern_analysis

        }

    except Exception as error:

        # -----------------------------------------
        # STANDARDIZED ERROR RESPONSE
        # -----------------------------------------

        return {

            "status": "error",

            "request_id": request_id,

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "message": "Analysis failed",

            "details": str(error)

        }