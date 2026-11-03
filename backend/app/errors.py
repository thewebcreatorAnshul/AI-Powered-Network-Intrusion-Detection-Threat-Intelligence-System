"""Consistent API error payloads that do not expose secrets or stack traces."""

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError
from starlette.exceptions import HTTPException as StarletteHTTPException


def error_payload(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}


class APIError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(
            status_code=status_code,
            detail={"code": code, "message": message},
        )


def raise_api_error(status_code: int, code: str, message: str) -> None:
    raise APIError(status_code, code, message)


def _payload_from_http_exception(exc: StarletteHTTPException) -> dict:
    detail = exc.detail
    if isinstance(detail, dict) and detail.get("code") and detail.get("message"):
        return error_payload(str(detail["code"]), str(detail["message"]))
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return error_payload("unauthenticated", "Authentication is required.")
    if exc.status_code == status.HTTP_403_FORBIDDEN:
        return error_payload("forbidden", "You do not have permission to access this resource.")
    return error_payload("http_error", "The request could not be completed.")


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    del request
    return JSONResponse(status_code=exc.status_code, content=_payload_from_http_exception(exc))


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    del request, exc
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_payload("validation_error", "Invalid request input."),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    del request
    if isinstance(exc, PyMongoError):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_payload(
                "database_unavailable",
                "The database is currently unavailable.",
            ),
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_payload(
            "internal_error",
            "An unexpected error occurred.",
        ),
    )
