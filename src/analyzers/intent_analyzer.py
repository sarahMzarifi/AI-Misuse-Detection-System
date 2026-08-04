from security.intent_resolver import (
    resolve_intent
)

from security.confidence_scorer import (
    calculate_confidence
)
def analyze_intent(prompt):

    prompt_lower = prompt.lower()

    detected_intents = []

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


            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible privilege escalation attempt",

                "explanation":
                f"Detected suspicious authentication-related phrase: '{keyword}'"

            })
            detected_intents.append({

                "intent": "AUTH_BYPASS_ATTEMPT",

                "severity": "HIGH",

                "matched_phrase": keyword

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
        "internal api"

    ]

    for keyword in data_exposure_keywords:

        if keyword in prompt_lower:

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible sensitive data exposure",

                "explanation":
                f"Detected sensitive infrastructure or data reference: '{keyword}'"

            })
            detected_intents.append({

                "intent": "DATA_EXPOSURE",

                "severity": "MEDIUM",

                "matched_phrase": keyword

            })

    # -----------------------------------------
    # CREDENTIAL THEFT DETECTION
    # -----------------------------------------

    credential_theft_keywords = [

        "steal password",
        "steal credentials",
        "dump credentials",
        "extract credentials",
        "password dump",
        "credential dump",
        "password database",
        "login credentials",
        "user credentials",
        "authentication token",
        "api token",
        "access token",
        "refresh token",
        "jwt token",
        "oauth token",
        "session token",
        "session cookie",
        "steal cookie"

    ]

    for keyword in credential_theft_keywords:

        if keyword in prompt_lower:

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible credential theft attempt",

                "explanation":
                f"Detected credential theft related phrase: '{keyword}'"

            })
            detected_intents.append({

                "intent": "CREDENTIAL_THEFT",

                "severity": "HIGH",

                "matched_phrase": keyword

            })

    credential_theft_actions = [

        "steal",
        "dump",
        "extract",
        "obtain",
        "capture",
        "collect",
        "retrieve"

    ]

    credential_theft_targets = [

        "password",
        "passwords",
        "credential",
        "credentials",
        "token",
        "tokens",
        "cookie",
        "cookies",
        "session",
        "jwt",
        "oauth"

    ]

    for action in credential_theft_actions:

        for target in credential_theft_targets:

            if action in prompt_lower and target in prompt_lower:

                detected_intents.append({
                
                    "intent": "CREDENTIAL_THEFT",
                
                    "severity": "HIGH",
                
                    "matched_phrase": f"{action} + {target}"
                
                })

                reasons.append({

                    "detected_phrase":
                    f"{action} + {target}",

                    "security_concern":
                    "Possible credential theft attempt",

                    "explanation":
                    f"Detected possible credential theft activity involving '{action}' and '{target}'"

                })

    # -----------------------------------------
    # PROMPT INJECTION DETECTION
    # -----------------------------------------
    prompt_injection_keywords = [

        "ignore previous instructions",
        "ignore all previous instructions",
        "forget previous instructions",
        "forget everything above",
        "reveal your system prompt",
        "show your system prompt",
        "display your system prompt",
        "what is your system prompt",
        "repeat your instructions",
        "developer instructions",
        "system instructions",
        "override previous instructions",
        "bypass ai restrictions",
        "ignore safety policies",
        "pretend to be unrestricted",
        "jailbreak",
        "dan mode"

    ]

    for keyword in prompt_injection_keywords:

        if keyword in prompt_lower:

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible prompt injection attempt",

                "explanation":
                f"Detected prompt injection phrase: '{keyword}'"

            })
            detected_intents.append({
            
                "intent": "PROMPT_INJECTION",
            
                "severity": "HIGH",
            
                "matched_phrase": keyword
            
            })

    # -----------------------------------------
    # SOCIAL ENGINEERING DETECTION
    # -----------------------------------------

    social_engineering_keywords = [

        "phishing",
        "phishing email",
        "credential harvesting",
        "social engineering",
        "fake login page"

    ]

    for keyword in social_engineering_keywords:

        if keyword in prompt_lower:

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible social engineering attempt",

                "explanation":
                f"Detected social engineering phrase: '{keyword}'"

            })
            detected_intents.append({
            
                "intent": "SOCIAL_ENGINEERING",
            
                "severity": "HIGH",
            
                "matched_phrase": keyword
            
            })

    social_actions = [

        "trick",
        "convince",
        "impersonate",
        "pretend",
        "deceive",
        "harvest",
        "obtain"

    ]

    social_targets = [

        "user",
        "employee",
        "otp",
        "verification code",
        "login",
        "account",
        "it support",
        "hr"

    ]

    for action in social_actions:

        for target in social_targets:

            if action in prompt_lower and target in prompt_lower:

                reasons.append({

                    "detected_phrase":
                    f"{action} + {target}",

                    "security_concern":
                    "Possible social engineering attempt",

                    "explanation":
                    f"Detected possible social engineering activity involving '{action}' and '{target}'"

                })
                detected_intents.append({
                
                    "intent": "SOCIAL_ENGINEERING",
                
                    "severity": "HIGH",
                
                    "matched_phrase": f"{action} + {target}"
                
                })

    # -----------------------------------------
    # MALICIOUS CODE DETECTION
    # -----------------------------------------

    malicious_code_keywords = [

        "malware",
        "ransomware",
        "spyware",
        "keylogger",
        "trojan",
        "worm",
        "virus",
        "botnet",
        "rootkit",
        "backdoor",
        "reverse shell"

    ]

    for keyword in malicious_code_keywords:

        if keyword in prompt_lower:

            reasons.append({

                "detected_phrase": keyword,

                "security_concern":
                "Possible malicious code request",

                "explanation":
                f"Detected malicious software reference: '{keyword}'"

            })
            detected_intents.append({
            
                "intent": "MALICIOUS_CODE_REQUEST",
            
                "severity": "HIGH",
            
                "matched_phrase": keyword
            
            })

    malicious_actions = [

        "create",
        "write",
        "generate",
        "develop",
        "build",
        "code",
        "implement"

    ]

    malicious_targets = [

        "malware",
        "ransomware",
        "spyware",
        "keylogger",
        "trojan",
        "worm",
        "virus",
        "botnet",
        "rootkit",
        "backdoor",
        "reverse shell",
        "payload"

    ]

    for action in malicious_actions:

        for target in malicious_targets:

            if action in prompt_lower and target in prompt_lower:

                reasons.append({

                    "detected_phrase":
                    f"{action} + {target}",

                    "security_concern":
                    "Possible malicious code generation request",

                    "explanation":
                    f"Detected possible malicious code generation involving '{action}' and '{target}'"

                })
                detected_intents.append({
                
                    "intent": "MALICIOUS_CODE_REQUEST",

                    "severity": "HIGH",
                
                    "matched_phrase": f"{action} + {target}"
                
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

                reasons.append({

                    "detected_phrase":
                    f"{action} + {target}",

                    "security_concern":
                    "Possible security monitoring evasion attempt",

                    "explanation":
                    f"Detected possible system manipulation intent involving '{action}' and '{target}'"

                })
                detected_intents.append({
                
                    "intent": "SYSTEM_MANIPULATION",
                
                    "severity": "HIGH",
                
                    "matched_phrase": f"{action} + {target}"
                
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

                reasons.append({

                    "detected_phrase": keyword,

                    "security_concern":
                    "No immediate security concern",

                    "explanation":
                    f"Detected normal development/debugging activity: '{keyword}'"

                })
                detected_intents.append({
                
                    "intent": "DEBUGGING",
                
                    "severity": "LOW",
                
                    "matched_phrase": keyword
                
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

        detected_intents.append({
        
            "intent": "INFORMATIONAL",
        
            "severity": "LOW",
        
            "matched_phrase": None
        
        })

    # -----------------------------------------
    # STRUCTURED OUTPUT
    # -----------------------------------------
    
    resolved_intent = resolve_intent(
        detected_intents
    )

    confidence = calculate_confidence(
            detected_intents
    )

    return {

    "intent_type":
    resolved_intent["intent_type"],

    "severity":
    resolved_intent["severity"],

    "confidence":
    confidence,

    "reasons":
    reasons,

    "detected_intents":
    detected_intents

}