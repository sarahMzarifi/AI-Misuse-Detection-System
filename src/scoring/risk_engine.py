# -----------------------------------------
# CENTRALIZED RISK WEIGHT CONFIGURATION
# -----------------------------------------

INTENT_SEVERITY_SCORES = {

    "LOW": 10,

    "MEDIUM": 40,

    "HIGH": 80

}


DETECTION_TYPE_SCORES = {

    "PASSWORD_DETECTED": 40,

    "API_KEY_DETECTED": 50,

    "EMAIL_DETECTED": 10

}


# -----------------------------------------
# CONFIDENCE ADJUSTMENT CONFIGURATION
# -----------------------------------------

CONFIDENCE_THRESHOLDS = {

    "HIGH": 75,

    "MEDIUM": 40

}


CONFIDENCE_PENALTIES = {

    "HIGH": 0,

    "MEDIUM": 5,

    "LOW": 10

}


# -----------------------------------------
# RISK SCORE LIMITS
# -----------------------------------------

MIN_RISK_SCORE = 0

MAX_RISK_SCORE = 100


# -----------------------------------------
# FINAL RISK CALCULATION ENGINE
# -----------------------------------------

def calculate_final_risk(
    detection_results,
    intent_analysis
):

    # -----------------------------------------
    # INITIALIZE SCORING VARIABLES
    # -----------------------------------------

    total_score = 0

    reasons = []


    # -----------------------------------------
    # PROCESS DETECTION RESULTS
    # -----------------------------------------

    for detection in detection_results:

        # -----------------------------------------
        # STANDARDIZED DETECTION OBJECT
        # -----------------------------------------

        detection_type = detection.get(
            "type"
        )

        if detection_type in DETECTION_TYPE_SCORES:

            total_score += (
                DETECTION_TYPE_SCORES[
                    detection_type
                ]
            )

            reasons.append(

                f"{detection_type} "
                f"contributed to risk score"

            )


    # -----------------------------------------
    # PROCESS INTENT ANALYSIS
    # -----------------------------------------

    intent_severity = intent_analysis.get(
        "severity",
        "LOW"
    )

    if intent_severity in INTENT_SEVERITY_SCORES:

        total_score += (
            INTENT_SEVERITY_SCORES[
                intent_severity
            ]
        )

        reasons.append(

            f"Intent severity "
            f"'{intent_severity}' "
            f"contributed to risk score"

        )


    # -----------------------------------------
    # PROCESS CONFIDENCE
    # -----------------------------------------

    confidence_data = intent_analysis.get(
        "confidence",
        {}
    )


    confidence_score = confidence_data.get(
        "score",
        0
    )


    # -----------------------------------------
    # DETERMINE CONFIDENCE LEVEL
    # -----------------------------------------

    if confidence_score >= CONFIDENCE_THRESHOLDS[
        "HIGH"
    ]:

        confidence_level = "HIGH"

    elif confidence_score >= CONFIDENCE_THRESHOLDS[
        "MEDIUM"
    ]:

        confidence_level = "MEDIUM"

    else:

        confidence_level = "LOW"


    # -----------------------------------------
    # APPLY CONFIDENCE ADJUSTMENT
    # -----------------------------------------

    confidence_penalty = CONFIDENCE_PENALTIES[
        confidence_level
    ]


    if confidence_penalty > 0:

        total_score -= confidence_penalty

        reasons.append(

            f"Confidence level "
            f"'{confidence_level}' "
            f"reduced risk score by "
            f"{confidence_penalty} points"

        )

    else:

        reasons.append(

            f"Confidence level "
            f"'{confidence_level}' "
            f"did not reduce risk score"

        )


    # -----------------------------------------
    # PREVENT NEGATIVE RISK SCORE
    # -----------------------------------------

    total_score = max(
        total_score,
        MIN_RISK_SCORE
    )


    # -----------------------------------------
    # NORMALIZE RISK SCORE
    # -----------------------------------------

    if total_score > MAX_RISK_SCORE:

        reasons.append(

            f"Raw risk score exceeded "
            f"{MAX_RISK_SCORE} and was normalized "
            f"to {MAX_RISK_SCORE}"

        )

        total_score = MAX_RISK_SCORE


    # -----------------------------------------
    # DETERMINE FINAL RISK LEVEL
    # -----------------------------------------

    if total_score >= 80:

        risk_level = "HIGH"

    elif total_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # -----------------------------------------
    # RETURN FINAL CENTRALIZED RISK RESULT
    # -----------------------------------------

    return {

        "risk_level":
        risk_level,

        "risk_score":
        total_score,

        "reasons":
        reasons

    }