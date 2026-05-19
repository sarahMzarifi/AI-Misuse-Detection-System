from datetime import datetime

# REQUEST COUNTER

request_counter = 0


# GENERATE UNIQUE REQUEST ID

def generate_request_id():

    global request_counter

    # INCREMENT COUNTER

    request_counter += 1

    # CURRENT DATE

    current_date = datetime.now().strftime(
        "%Y%m%d"
    )

    # STRUCTURED REQUEST ID

    request_id = (

        f"REQ-"

        f"{current_date}-"

        f"{request_counter:04d}"

    )

    return request_id