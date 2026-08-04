"""
-----------------------------------------
CONFIDENCE SCORER
-----------------------------------------

Calculates an overall confidence score
based on all detected intents.

The scorer removes duplicate and
semantically equivalent matched
phrases so repeated detections do
not inflate the confidence score.

Example:

credential
credentials

Both contribute only once.

This module does NOT decide the
intent or risk.

It only measures confidence.
"""

# -----------------------------------------
# SEVERITY WEIGHTS
# -----------------------------------------

SEVERITY_WEIGHTS = {

    "LOW": 10,

    "MEDIUM": 35,

    "HIGH": 60

}

# -----------------------------------------
# MAXIMUM CONFIDENCE
# -----------------------------------------

MAX_CONFIDENCE = 100

# -----------------------------------------
# CONFIDENCE LEVELS
# -----------------------------------------

LOW_CONFIDENCE = "LOW"

MEDIUM_CONFIDENCE = "MEDIUM"

HIGH_CONFIDENCE = "HIGH"

# -----------------------------------------
# NORMALIZED SECURITY TERMS
# -----------------------------------------

NORMALIZED_TERMS = {

    "credentials": "credential",

    "passwords": "password",

    "tokens": "token",

    "cookies": "cookie",

    "sessions": "session"

}

# -----------------------------------------
# NORMALIZE MATCHED PHRASE
# -----------------------------------------

def normalize_phrase(matched_phrase):

    """
    Converts semantically equivalent
    phrases into a canonical form.

    Example

    credentials -> credential
    tokens -> token
    steal + credentials -> steal + credential
    """

    if matched_phrase is None:

        return None

    normalized_words = []

    words = matched_phrase.lower().split()

    for word in words:

        normalized_words.append(

            NORMALIZED_TERMS.get(

                word,

                word

            )

        )

    return " ".join(normalized_words)

# -----------------------------------------
# CALCULATE CONFIDENCE
# -----------------------------------------

def calculate_confidence(detected_intents):

    """
    Calculates confidence from all
    detected intents.

    Duplicate semantic matches are
    ignored.
    """

    confidence_score = 0

    seen_phrases = set()

    for detection in detected_intents:

        matched_phrase = normalize_phrase(

            detection.get(

                "matched_phrase"

            )

        )

        severity = detection.get(

            "severity",

            "LOW"

        )

        # -----------------------------
        # Skip duplicate semantic matches
        # -----------------------------

        if matched_phrase in seen_phrases:

            continue

        seen_phrases.add(

            matched_phrase

        )

        confidence_score += SEVERITY_WEIGHTS.get(

            severity,

            0

        )

    # -----------------------------
    # Cap at maximum
    # -----------------------------

    confidence_score = min(

        confidence_score,

        MAX_CONFIDENCE

    )

    # -----------------------------
    # Determine confidence level
    # -----------------------------

    if confidence_score >= 75:

        confidence_level = HIGH_CONFIDENCE

    elif confidence_score >= 40:

        confidence_level = MEDIUM_CONFIDENCE

    else:

        confidence_level = LOW_CONFIDENCE

    # -----------------------------
    # Return structured result
    # -----------------------------

    return {

        "score": confidence_score,

        "level": confidence_level

    }