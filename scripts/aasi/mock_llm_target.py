#!/usr/bin/env python3
"""Tiny lab LLM/agent HTTP stub for live AASI scanner tests.

Listens on 127.0.0.1:18080 by default.
Endpoints:
  GET  /health
  POST /v1/chat/completions   (OpenAI-shaped)
  POST /chat                  (safelabs-style prompt body)
  POST /                      (generic JSON prompt/messages)

From Docker scanners on Desktop, use host.docker.internal:18080.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST = "0.0.0.0"
PORT = 18080


def _reply_text(prompt: str) -> str:
    low = (prompt or "").lower()
    # Keep responses boring so scanners do not invent confirmed vulns from the stub.
    if "system prompt" in low or "developer message" in low:
        return "I cannot reveal system instructions. How else can I help?"
    if "ignore" in low and "rule" in low:
        return "I must follow my safety policies. Please rephrase your request."
    if "api key" in low or "secret" in low:
        return "I do not have access to API keys or secrets."
    return f"Lab stub received your message ({len(prompt)} chars). This is a safe test reply."


def _extract_prompt(payload: object) -> str:
    if not isinstance(payload, dict):
        return str(payload)
    if isinstance(payload.get("prompt"), str):
        return payload["prompt"]
    if isinstance(payload.get("input"), str):
        return payload["input"]
    if isinstance(payload.get("message"), str):
        return payload["message"]
    msgs = payload.get("messages")
    if isinstance(msgs, list) and msgs:
        last = msgs[-1]
        if isinstance(last, dict) and isinstance(last.get("content"), str):
            return last["content"]
    return json.dumps(payload)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter lab logs
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: dict | str, content_type: str = "application/json") -> None:
        raw = body if isinstance(body, (bytes, bytearray)) else (
            body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        )
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/health"):
            self._send(200, {"ok": True, "service": "aasi-mock-llm"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            payload = {"prompt": raw.decode("utf-8", errors="replace")}
        prompt = _extract_prompt(payload)
        text = _reply_text(prompt)
        if self.path.startswith("/v1/chat/completions"):
            self._send(
                200,
                {
                    "id": "lab-stub",
                    "object": "chat.completion",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
                    "usage": {"prompt_tokens": max(1, len(prompt) // 4), "completion_tokens": max(1, len(text) // 4)},
                },
            )
            return
        # safelabs / generic agent shapes
        self._send(200, {"response": text, "output": text, "text": text, "content": text})


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"aasi mock LLM listening on http://127.0.0.1:{PORT} (Docker: host.docker.internal:{PORT})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
