# -----------------------------------------
# SECURITY DECISIONS
# -----------------------------------------

ALLOW = "ALLOW"

ESCALATE = "ESCALATE"

STRICT_MONITORING = "STRICT_MONITORING"

BLOCK = "BLOCK"

# -----------------------------------------
# SECURITY ESCALATION THRESHOLDS
# -----------------------------------------

STRICT_MONITORING_THRESHOLD = 3

BLOCK_THRESHOLD = 5

# -----------------------------------------
# MONITORING STATES
# -----------------------------------------

NORMAL_MONITORING = (
    "NORMAL_MONITORING"
)

ELEVATED_MONITORING = (
    "ELEVATED_MONITORING"
)

HIGH_ALERT_MONITORING = (
    "HIGH_ALERT_MONITORING"
)

CRITICAL_MONITORING = (
    "CRITICAL_MONITORING"
)

# -----------------------------------------
# RESPONSE ACTIONS
# -----------------------------------------

REQUEST_ALLOWED = (
    "REQUEST_ALLOWED"
)

REQUEST_ALLOWED_WITH_MONITORING = (
    "REQUEST_ALLOWED_WITH_MONITORING"
)

REQUEST_ALLOWED_UNDER_OBSERVATION = (
    "REQUEST_ALLOWED_UNDER_OBSERVATION"
)

REQUEST_DENIED = (
    "REQUEST_DENIED"
)

# -----------------------------------------
# EVENT SEVERITY LEVELS
# -----------------------------------------

INFO = "INFO"

WARNING = "WARNING"

CRITICAL = "CRITICAL"