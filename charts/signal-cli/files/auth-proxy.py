#!/usr/bin/env python3
"""Token proxy in front of signal-cli-rest-api (which has no auth and listens on every interface; the chart's
NetworkPolicy leaves only this proxy's port reachable). Stdlib only.

Tokens: $TOKENS_FILE (a Secret), JSON {"<sha256 hex of the token>": rule}, re-read on every request. Rule:
  {"name": "claude", "number": "+48...", "recipients": ["+48..."]}   only:
    GET  /v1/receive/<number>        (websocket: incoming messages)
    POST /v2/send                    number == <number>, every recipient in recipients (no groups)
    POST /v1/reactions/<number>      recipient in recipients
  {"name": "admin", "admin": true}  everything
GET /v1/health needs no token (probes). Anything else: 403. Client sends "Authorization: Bearer <token>".
One request per connection (Connection: close upstream), so nothing unchecked can follow a checked request.
"""
import asyncio, hashlib, hmac, json, os, urllib.parse

UPSTREAM = ("127.0.0.1", int(os.environ.get("UPSTREAM_PORT", "8080")))
PORT = int(os.environ.get("PORT", "8081"))
TOKENS_FILE = os.environ.get("TOKENS_FILE", "/etc/signal-cli-proxy/tokens.json")
MAX_BODY = 64 << 20  # base64 attachments
DROP = {"authorization", "connection", "keep-alive", "proxy-connection", "expect", "te", "trailer"}


def rule_for(token):
    if not token:
        return None
    try:
        rules = json.load(open(TOKENS_FILE))
    except (OSError, ValueError) as e:
        print("tokens file:", e, flush=True)
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    return next((r for k, r in rules.items() if hmac.compare_digest(k, h)), None)


def allowed(method, path, body, rule):
    if rule.get("admin"):
        return True
    num, rcpt = rule.get("number"), set(rule.get("recipients") or [])
    if method == "GET" and path == f"/v1/receive/{num}":
        return True
    try:
        b = json.loads(body or b"{}")
    except ValueError:
        return False
    if not isinstance(b, dict):
        return False
    if method == "POST" and path == "/v2/send":
        r = b.get("recipients")
        return b.get("number") == num and isinstance(r, list) and bool(r) and set(r) <= rcpt
    if method == "POST" and path == f"/v1/reactions/{num}":
        return b.get("recipient") in rcpt
    return False


async def reply(w, code, text):
    w.write(f"HTTP/1.1 {code} {text}\r\nContent-Type: text/plain\r\nContent-Length: {len(text) + 1}\r\n"
            f"Connection: close\r\n\r\n{text}\n".encode())
    await w.drain()


async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(cr, cw):
    who = "-"
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 30)
        if len(head) > 32768:
            return await reply(cw, 431, "Request Header Fields Too Large")
        lines = head.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ")
        hdrs = [l.split(":", 1) for l in lines[1:] if ":" in l]
        h = {k.strip().lower(): v.strip() for k, v in hdrs}
        raw = target.split("?", 1)[0]
        path = urllib.parse.unquote(raw)
        if sum(k.strip().lower() == "content-length" for k, _ in hdrs) > 1 \
                or "transfer-encoding" in h or "/." in path or "//" in path or not path.startswith("/"):
            return await reply(cw, 400, "Bad Request")
        n = int(h.get("content-length") or 0)
        if n > MAX_BODY:
            return await reply(cw, 413, "Payload Too Large")
        if h.get("expect", "").lower() == "100-continue":
            cw.write(b"HTTP/1.1 100 Continue\r\n\r\n")
        body = await asyncio.wait_for(cr.readexactly(n), 120) if n else b""
        auth = h.get("authorization", "")
        rule = rule_for(auth[7:].strip() if auth.lower().startswith("bearer ") else "")
        who = (rule or {}).get("name", "-")
        if not (method == "GET" and path == "/v1/health"):
            if not rule:
                print(f"401 {method} {raw}", flush=True)
                return await reply(cw, 401, "Unauthorized")
            if not allowed(method, path, body, rule):
                print(f"403 {who} {method} {raw}", flush=True)
                return await reply(cw, 403, "Forbidden")
        upgrade = h.get("upgrade", "").lower() == "websocket" and method == "GET"
        ur, uw = await asyncio.open_connection(*UPSTREAM)
        out = [f"{method} {target} {version}"] + [f"{k}:{v}" for k, v in hdrs if k.strip().lower() not in DROP]
        out += ["Connection: Upgrade"] if upgrade else ["Connection: close"]
        uw.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await uw.drain()
        if method != "GET" or path != "/v1/health":
            print(f"ok {who} {method} {raw}", flush=True)
        if upgrade:  # websocket: both ways until either side closes
            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
        else:  # one request per connection: the client's further bytes are never forwarded
            await pipe(ur, cw)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError, ConnectionError, OSError) as e:
        if not isinstance(e, asyncio.IncompleteReadError) or e.partial:
            print(f"error {who}: {e!r}", flush=True)
    finally:
        try:
            cw.close()
        except Exception:
            pass


async def main():
    srv = await asyncio.start_server(handle, "0.0.0.0", PORT, limit=65536)
    print(f"listening on {PORT}, upstream {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
