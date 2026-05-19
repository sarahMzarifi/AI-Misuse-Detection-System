# -----------------------------------------
# IN-MEMORY THREAT HISTORY STORAGE
# -----------------------------------------

threat_history = []


# -----------------------------------------
# STORE STRUCTURED SECURITY EVENT
# -----------------------------------------

def store_threat_event(
    security_event
):

    threat_history.append(
        security_event
    )


# -----------------------------------------
# RETRIEVE THREAT HISTORY
# -----------------------------------------

def get_threat_history():

    return threat_history