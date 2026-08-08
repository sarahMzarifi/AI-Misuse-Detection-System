# -----------------------------------------
# INTENT RESOLVER
# -----------------------------------------

"""
This module is responsible for selecting the
best-supported primary intent detected during
prompt analysis.

The Intent Analyzer is responsible only for
detecting suspicious behaviors.

This resolver is responsible for deciding
which detected intent becomes the final
intent classification.

Decision order:

1. Intent priority
2. Severity
3. Number of supporting detections

This keeps the resolver deterministic while
using the richer detection objects introduced
by the confidence and standard detection stages.
"""

from core.security_constants import (
    INTENT_PRIORITY
)


# -----------------------------------------
# SEVERITY PRIORITY
# -----------------------------------------

SEVERITY_PRIORITY = {

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3

}


# -----------------------------------------
# RESOLVE FINAL INTENT
# -----------------------------------------

def resolve_intent(detected_intents):

    """
    Selects the best-supported primary intent
    from all detected intents.

    Parameters
    ----------
    detected_intents : list

        List containing detection objects such as:

        {
            "intent": "...",
            "severity": "...",
            "matched_phrase": "...",
            "detector": "..."
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
    # COUNT SUPPORTING DETECTIONS
    # -----------------------------------------

    intent_support = {}

    for detection in detected_intents:

        intent = detection.get(
            "intent"
        )

        if intent:

            intent_support[intent] = (
                intent_support.get(intent, 0) + 1
            )


    # -----------------------------------------
    # INITIALIZE WINNER
    # -----------------------------------------

    winning_intent = detected_intents[0]

    winning_intent_name = winning_intent.get(
        "intent"
    )

    highest_priority = INTENT_PRIORITY.get(

        winning_intent_name,

        0

    )

    highest_severity = SEVERITY_PRIORITY.get(

        winning_intent.get(
            "severity",
            "LOW"
        ),

        1

    )

    highest_support = intent_support.get(

        winning_intent_name,

        1

    )


    # -----------------------------------------
    # COMPARE ALL DETECTED INTENTS
    # -----------------------------------------

    for detected in detected_intents:

        intent = detected.get(
            "intent"
        )

        current_priority = INTENT_PRIORITY.get(

            intent,

            0

        )

        current_severity = SEVERITY_PRIORITY.get(

            detected.get(
                "severity",
                "LOW"
            ),

            1

        )

        current_support = intent_support.get(

            intent,

            1

        )


        # -------------------------------------
        # PRIORITY IS THE PRIMARY FACTOR
        # -------------------------------------

        if current_priority > highest_priority:

            winning_intent = detected

            highest_priority = current_priority

            highest_severity = current_severity

            highest_support = current_support

            continue


        # -------------------------------------
        # SEVERITY BREAKS PRIORITY TIES
        # -------------------------------------

        if current_priority == highest_priority:

            if current_severity > highest_severity:

                winning_intent = detected

                highest_severity = current_severity

                highest_support = current_support

                continue


            # ---------------------------------
            # SUPPORTING EVIDENCE BREAKS TIES
            # ---------------------------------

            if (
                current_severity == highest_severity
                and current_support > highest_support
            ):

                winning_intent = detected

                highest_support = current_support


    # -----------------------------------------
    # RETURN FINAL DECISION
    # -----------------------------------------

    return {

        "intent_type":

        winning_intent["intent"],

        "severity":

        winning_intent.get(
            "severity",
            "LOW"
        )

    }