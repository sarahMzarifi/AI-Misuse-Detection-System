# -----------------------------------------
# INTENT RESOLVER
# -----------------------------------------

"""
This module is responsible for selecting the
highest-priority intent detected during prompt
analysis.

The Intent Analyzer is responsible only for
detecting suspicious behaviors.

This resolver is responsible for deciding
which detected intent becomes the final
intent classification.

Keeping this logic separate improves
maintainability, scalability, and follows
the Single Responsibility Principle (SRP).
"""

from core.security_constants import (
    INTENT_PRIORITY
)

# -----------------------------------------
# RESOLVE FINAL INTENT
# -----------------------------------------

def resolve_intent(detected_intents):

    """
    Selects the highest-priority intent from
    all detected intents.

    Parameters
    ----------
    detected_intents : list

        List containing dictionaries in the
        following format:

        {
            "intent": "...",
            "severity": "...",
            "reason": {...}
        }

    Returns
    -------
    dict

        Standardized final intent object.
    """

    # -----------------------------------------
    # DEFAULT SAFE RESPONSE
    # -----------------------------------------

    if not detected_intents:

        return {

            "intent_type": "INFORMATIONAL",

            "severity": "LOW"

        }

    # -----------------------------------------
    # INITIALIZE WINNER
    # -----------------------------------------

    winning_intent = detected_intents[0]

    highest_priority = INTENT_PRIORITY.get(

        winning_intent["intent"],

        0

    )

    # -----------------------------------------
    # COMPARE ALL DETECTED INTENTS
    # -----------------------------------------

    for detected in detected_intents[1:]:

        current_priority = INTENT_PRIORITY.get(

            detected["intent"],

            0

        )

        if current_priority > highest_priority:

            highest_priority = current_priority

            winning_intent = detected

    # -----------------------------------------
    # RETURN FINAL DECISION
    # -----------------------------------------

    return {

        "intent_type":

        winning_intent["intent"],

        "severity":

        winning_intent["severity"]

    }