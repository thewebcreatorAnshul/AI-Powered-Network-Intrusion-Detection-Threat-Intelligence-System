"""Small ASGI request guards for resource-sensitive endpoints."""

import json


class UploadBodyLimitMiddleware:
    """Reject over-limit upload bodies before Starlette parses/spools multipart data."""

    def __init__(self, app, *, path: str, max_body_bytes: int) -> None:
        self.app = app
        self.path = path
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST" or scope.get("path") != self.path:
            await self.app(scope, receive, send)
            return

        request_headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = request_headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_body_bytes:
                    await self._send_too_large(send)
                    return
            except ValueError:
                pass

        total = 0
        exceeded = False

        async def limited_receive():
            nonlocal total, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_body_bytes:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def limited_send(message):
            if not exceeded:
                await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded:
            await self._send_too_large(send)

    async def _send_too_large(self, send) -> None:
        body = json.dumps({
            "error": {
                "code": "upload_too_large",
                "message": "Upload exceeds the maximum allowed request size.",
            },
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})
