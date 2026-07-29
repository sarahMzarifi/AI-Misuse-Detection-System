# -----------------------------------------
# THREAT CATEGORIES
# -----------------------------------------

"""
Standardized threat classification constants
used throughout the AI Misuse Detection System.

This module centralizes all threat-related
classification values to eliminate hardcoded
strings and maintain consistency across the
classification, policy, reporting, and
monitoring layers.
"""


# -----------------------------------------
# THREAT CATEGORIES
# -----------------------------------------

SAFE_REQUEST = "SAFE_REQUEST"

PROMPT_INJECTION = "PROMPT_INJECTION"

SYSTEM_MANIPULATION = "SYSTEM_MANIPULATION"

DATA_EXFILTRATION = "DATA_EXFILTRATION"

CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"

SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"

MALICIOUS_CODE_REQUEST = "MALICIOUS_CODE_REQUEST"

SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"

UNKNOWN_THREAT = "UNKNOWN_THREAT"


# -----------------------------------------
# THREAT FAMILIES
# -----------------------------------------

NO_THREAT = "NO_THREAT"

INSTRUCTION_MANIPULATION = "INSTRUCTION_MANIPULATION"

INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"

AUTHENTICATION_ATTACK = "AUTHENTICATION_ATTACK"

SOCIAL_ENGINEERING_ATTACK = "SOCIAL_ENGINEERING_ATTACK"

MALICIOUS_CODE_GENERATION = "MALICIOUS_CODE_GENERATION"

ABNORMAL_BEHAVIOR = "ABNORMAL_BEHAVIOR"

UNCLASSIFIED = "UNCLASSIFIED"


# -----------------------------------------
# THREAT TYPES
# -----------------------------------------

SAFE = "SAFE"

BEHAVIORAL = "BEHAVIORAL"

SYSTEM = "SYSTEM"

ACCESS = "ACCESS"

DATA = "DATA"

CODE = "CODE"

UNKNOWN = "UNKNOWN"


# -----------------------------------------
# CONFIDENCE LEVELS
# -----------------------------------------

LOW_CONFIDENCE = "LOW"

MEDIUM_CONFIDENCE = "MEDIUM"

HIGH_CONFIDENCE = "HIGH"


# -----------------------------------------
# RESPONSE PRIORITIES
# -----------------------------------------

LOW_PRIORITY = "LOW"

MEDIUM_PRIORITY = "MEDIUM"

HIGH_PRIORITY = "HIGH"

CRITICAL_PRIORITY = "CRITICAL"