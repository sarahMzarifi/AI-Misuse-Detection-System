def analyze_intent(prompt):

    prompt_lower = prompt.lower()

    intent_type = "INFORMATIONAL"
    severity = "LOW"

    reasons = []

    # -----------------------------------------
    # AUTHENTICATION / ACCESS BYPASS DETECTION
    # -----------------------------------------

    auth_bypass_keywords = [
        "bypass authentication",
        "bypass admin authentication",
        "bypass admin login",
        "admin access",
        "disable security",
        "crack password",
        "exploit login",
        "privilege escalation",
        "authentication bypass"
    ]

    for keyword in auth_bypass_keywords:

        if keyword in prompt_lower:

            intent_type = "AUTH_BYPASS_ATTEMPT"
            severity = "HIGH"

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible privilege escalation attempt",

                "explanation":
                f"Detected suspicious authentication-related phrase: '{keyword}'"
            })

    # -----------------------------------------
    # DATA EXPOSURE DETECTION
    # -----------------------------------------

    data_exposure_keywords = [
        "api key",
        "database credential",
        "internal server",
        "confidential document",
        "private key",
        "production server",
        "server credential",
        "private server credential",
        "credential",
        "internal api"
    ]

    for keyword in data_exposure_keywords:

        if keyword in prompt_lower:

            intent_type = "DATA_EXPOSURE"

            if severity != "HIGH":
                severity = "MEDIUM"

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible sensitive data exposure",

                "explanation":
                f"Detected sensitive infrastructure or data reference: '{keyword}'"
            })

    # -----------------------------------------
    # SYSTEM MANIPULATION DETECTION
    # -----------------------------------------

    manipulation_keywords = [
        "disable",
        "evade",
        "avoid",
        "remove",
        "hide"
    ]

    security_targets = [
        "firewall",
        "monitoring",
        "logs",
        "activity",
        "detection"
    ]

    for action in manipulation_keywords:

        for target in security_targets:

            if action in prompt_lower and target in prompt_lower:

                intent_type = "SYSTEM_MANIPULATION"
                severity = "HIGH"

                reasons.append({

                    "detected_phrase":
                    f"{action} + {target}",

                    "security_concern":
                    "Possible security monitoring evasion attempt",

                    "explanation":
                    f"Detected possible system manipulation intent involving '{action}' and '{target}'"
                })

    # -----------------------------------------
    # DEBUGGING / NORMAL DEVELOPMENT DETECTION
    # -----------------------------------------

    debugging_keywords = [
        "debug",
        "fix this code",
        "optimize function",
        "resolve error",
        "improve performance"
    ]

    for keyword in debugging_keywords:

        if keyword in prompt_lower:

            # Only classify as debugging
            # if no higher-risk intent already exists

            if intent_type == "INFORMATIONAL":

                intent_type = "DEBUGGING"
                severity = "LOW"

                reasons.append({

                    "detected_phrase": keyword,

                    "security_concern":
                    "No immediate security concern",

                    "explanation":
                    f"Detected normal development/debugging activity: '{keyword}'"
                })

    # -----------------------------------------
    # DEFAULT SAFE CLASSIFICATION
    # -----------------------------------------

    if not reasons:

        reasons.append({

            "detected_phrase": "None",

            "security_concern":
            "No immediate security concern",

            "explanation":
            "No suspicious or security-sensitive intent detected"
        })

    # -----------------------------------------
    # STRUCTURED OUTPUT
    # -----------------------------------------

    return {

        "intent_type": intent_type,

        "severity": severity,

        "reasons": reasons
    }