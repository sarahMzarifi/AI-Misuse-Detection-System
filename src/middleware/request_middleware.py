import time

from fastapi import Request

from starlette.middleware.base import (
    BaseHTTPMiddleware
)

# -----------------------------------------
# REQUEST MONITORING MIDDLEWARE
# -----------------------------------------

class RequestMonitoringMiddleware(
    BaseHTTPMiddleware
):

    async def dispatch(

        self,

        request: Request,

        call_next

    ):

        # -----------------------------------------
        # START REQUEST TIMER
        # -----------------------------------------

        start_time = time.time()

        # -----------------------------------------
        # PROCESS REQUEST
        # -----------------------------------------

        response = await call_next(request)

        # -----------------------------------------
        # STOP REQUEST TIMER
        # -----------------------------------------

        process_time = (
            time.time() - start_time
        )
        
        # -----------------------------------------
        # REQUEST TELEMETRY LOG
        # -----------------------------------------

        print(

            f"[MIDDLEWARE] "

            f"{request.method} "

            f"{request.url.path} "

            f"Status={response.status_code} "

            f"Time={process_time:.4f}s"

        )

        # -----------------------------------------
        # ADD PROCESSING TIME HEADER
        # -----------------------------------------

        response.headers[
            "X-Process-Time"
        ] = str(process_time)

        # -----------------------------------------
        # RETURN RESPONSE
        # -----------------------------------------

        return response