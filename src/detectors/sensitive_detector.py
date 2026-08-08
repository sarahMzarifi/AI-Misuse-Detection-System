import re


# -----------------------------------------
# SENSITIVE DATA DETECTOR
# -----------------------------------------

def detect_sensitive_data(text):

    findings = []

    # -----------------------------------------
    # EMAIL PATTERN
    # -----------------------------------------

    email_pattern = (
        r'\b[A-Za-z0-9._%+-]+'
        r'@[A-Za-z0-9.-]+'
        r'\.[A-Z|a-z]{2,}\b'
    )

    # -----------------------------------------
    # API KEY PATTERN
    # -----------------------------------------

    api_pattern = r'sk-[A-Za-z0-9-]+'

    # -----------------------------------------
    # PASSWORD PATTERN
    # -----------------------------------------

    password_pattern = r'password\s*=\s*\w+'

    # -----------------------------------------
    # DETECT MATCHES
    # -----------------------------------------

    emails = re.findall(
        email_pattern,
        text
    )

    apis = re.findall(
        api_pattern,
        text
    )

    passwords = re.findall(
        password_pattern,
        text
    )

    # -----------------------------------------
    # STORE EMAIL FINDINGS
    # -----------------------------------------

    if emails:

        findings.append({

            "type":
            "EMAIL_DETECTED",

            "severity":
            "LOW",

            "matched_values":
            emails,

            "detector":
            "SensitiveDataDetector"

        })

    # -----------------------------------------
    # STORE API KEY FINDINGS
    # -----------------------------------------

    if apis:

        findings.append({

            "type":
            "API_KEY_DETECTED",

            "severity":
            "HIGH",

            "matched_values":
            apis,

            "detector":
            "SensitiveDataDetector"

        })

    # -----------------------------------------
    # STORE PASSWORD FINDINGS
    # -----------------------------------------

    if passwords:

        findings.append({

            "type":
            "PASSWORD_DETECTED",

            "severity":
            "HIGH",

            "matched_values":
            passwords,

            "detector":
            "SensitiveDataDetector"

        })

    # -----------------------------------------
    # RETURN STANDARDIZED FINDINGS
    # -----------------------------------------

    return findings