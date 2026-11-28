#!/usr/bin/env python3
"""Token proxy in front of signal-cli-rest-api (which has no auth and listens on every interface; the chart's
NetworkPolicy leaves only this proxy's port reachable). Stdlib only.

Tokens: $TOKENS_FILE (Secret from values proxy.tokens, or proxy.tokensSecret), JSON
{"<sha256 hex of the token>": rule}, re-read on every request. Rule:
  {"name": "claude", "number": "+48...", "recipients": ["+48...", "group.<id>"], "allow": [...]}
  allow (default send, react, receive), each only for <number>:
    send     POST /v2/send                         sender <number>, every recipient in recipients
    react    POST|DELETE /v1/reactions/<number>    recipient in recipients
    delete   DELETE /v1/remote-delete/<number>     delete for everyone, recipient in recipients (not default)
    receive  GET /v1/receive/<number>              websocket: ALL incoming messages of the account (router mode: see below)
    read     GET /v1/contacts/<number>, GET /v1/groups/<number>[/<group id>]
    groups   POST /v1/groups/<number>/<group id>/join|quit, for group ids in recipients
    attachments  GET /v1/attachments/<id>          router mode: only files of messages queued for this rule
                                                   (until acknowledged); otherwise needs receive too (not default)
    agents   /v1/agents/...                        agent bus, router mode only (see below; not default)
  A group is a recipient like a number ("group.<id>", as /v1/groups lists it).
  {"name": "admin", "admin": true}  everything
Router mode ($QUEUE_DIR set; otherwise receive is piped as above): the proxy keeps one websocket to rest-api per number
with a receive rule (rescanned every 60 s; rest-api only fetches from Signal while one is attached) and routes each
message by conversation (group.<id> or sender number) to every rule whose recipients contain it (admin: all). Per rule
$QUEUE_DIR/<name>.jsonl keeps {"id", "t", "msg"} lines (7 days), so a client sees only its own conversations and
misses nothing while offline. GET /v1/receive/<number>[?after=<id>] (websocket) streams new messages, each the original
frame plus a top-level "id"; with after=<id> it first drops entries <= id (acknowledged) and replays the newer ones,
without it nothing old is sent. When a message from a number is queued while the rule has no client, one notice per
offline period goes to that conversation ("<label or name> is offline"; optional rule field "label").
Agent bus (router mode, allow "agents"; admin too): coding-agent sessions on different PCs (one token per PC, PC name =
rule label, else name; keep labels unique) message each other. Every /v1/agents/ endpoint needs agents (else 403):
  PUT  /v1/agents/sessions  {"sessions": [{"id", "harness", "title", "cwd", "status"}]} replaces this PC's list (in
       memory, lost on restart: clients re-publish every few minutes). <= 64 sessions, body <= 64 KB, strings cut to
       id/harness/status 128, title 200, cwd 300. 204.
  GET  /v1/agents/sessions  200 {"pcs": [{"pc", "online", "updated", "sessions"}]}: every agents rule that published
       in the last 10 min (older lists are dropped); online = that rule has a websocket client attached.
  POST /v1/agents/send      {"to": {"pc", "session"}, "from": {"session", "title"}, "text"} (text <= 16 KB) queues
       {"agent": {"from": {"pc", "session", "title"}, "to": {...}, "text", "id"}} for the rule whose PC name is to.pc
       (must have agents, else 404; its own PC is fine), like any routed message (ids, replay, live push; no offline
       notice). from.pc is the sender's PC name (set here, not by the client). 200 {"id", "online"}. 60 sends per
       10 min per sending rule, then 429. The target needs receive (websocket) to get them.
  Errors: 400 bad JSON/fields, 404 unknown PC or endpoint, 405 wrong method, 413 too large, 503 not in router mode.
GET /v1/health needs no token (probes). Anything else: 403. Client sends "Authorization: Bearer <token>".
One request per connection (Connection: close upstream), so nothing unchecked can follow a checked request.
"""
import asyncio, base64, collections, hashlib, hmac, json, os, time, urllib.parse

UPSTREAM = ("127.0.0.1", int(os.environ.get("UPSTREAM_PORT", "8080")))
PORT = int(os.environ.get("PORT", "8081"))
TOKENS_FILE = os.environ.get("TOKENS_FILE", "/etc/signal-cli-proxy/tokens.json")
MAX_BODY = 64 << 20  # base64 attachments
QUEUE_DIR = os.environ.get("QUEUE_DIR")
KEEP = 7 * 86400
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
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


DEFAULT_ALLOW = ("send", "react", "receive")


def allowed(method, path, body, rule):
    if rule.get("admin"):
        return True
    num, rcpt = rule.get("number"), set(rule.get("recipients") or [])
    allow = set(rule.get("allow") or DEFAULT_ALLOW)
    if method == "GET":
        if path == f"/v1/receive/{num}":
            return "receive" in allow
        parts = path.split("/")  # "", v1, groups|contacts, <num>[, <group id>]
        if len(parts) == 4 and parts[1:3] == ["v1", "attachments"]:
            return "attachments" in allow and (routed_attachment(rule["name"], parts[3]) if QUEUE_DIR else "receive" in allow)
        return "read" in allow and parts[1:4] in (["v1", "contacts", num], ["v1", "groups", num]) and len(parts) <= 5
    if method == "POST" and "groups" in allow:
        parts = path.split("/")
        if len(parts) == 6 and parts[1:4] == ["v1", "groups", num] and parts[5] in ("join", "quit"):
            return parts[4].startswith("group.") and parts[4] in rcpt
    try:
        b = json.loads(body or b"{}")
    except ValueError:
        return False
    if not isinstance(b, dict):
        return False
    if method == "POST" and path == "/v2/send":
        r = b.get("recipients")
        return "send" in allow and b.get("number") == num and isinstance(r, list) and bool(r) and set(r) <= rcpt
    if method in ("POST", "DELETE") and path == f"/v1/reactions/{num}":
        return "react" in allow and b.get("recipient") in rcpt
    if method == "DELETE" and path == f"/v1/remote-delete/{num}":
        return "delete" in allow and b.get("recipient") in rcpt
    return False


def rules():
    try:
        return list(json.load(open(TOKENS_FILE)).values())
    except (OSError, ValueError) as e:
        print("tokens file:", e, flush=True)
        return []


def can_receive(rule):
    return "receive" in (rule.get("allow") or DEFAULT_ALLOW)


# --- minimal websocket (RFC 6455) ---
def ws_send(w, data, op=1, mask=False):
    n, m = len(data), 128 if mask else 0
    head = bytes([128 | op]) + (bytes([m | n]) if n < 126 else bytes([m | 126]) + n.to_bytes(2, "big") if n < 65536
                                else bytes([m | 127]) + n.to_bytes(8, "big"))
    if mask:
        key = os.urandom(4)
        head += key
        data = bytes(c ^ key[i % 4] for i, c in enumerate(data))
    w.write(head + data)


async def ws_read(r, w, mask):
    """Next whole message (bytes, fragments joined); answers ping, None on close. mask: we are the client."""
    msg = b""
    while True:
        b1, b2 = await r.readexactly(2)
        n = b2 & 127
        if n > 125:
            n = int.from_bytes(await r.readexactly(2 if n == 126 else 8), "big")
        if n > MAX_BODY:
            raise ValueError("websocket frame too large")
        key = await r.readexactly(4) if b2 & 128 else None
        data = await r.readexactly(n)
        if key:
            data = bytes(c ^ key[i % 4] for i, c in enumerate(data))
        op = b1 & 15
        if op == 8:
            ws_send(w, data[:2], 8, mask)
            return None
        if op == 9:
            ws_send(w, data, 10, mask)
        elif op < 8:
            msg += data
            if b1 & 128:
                return msg


# --- router ---
last_id = 0
clients = {}  # rule name -> set of asyncio.Queue of connected clients
notified = set()  # rule names whose current offline period already got a notice


def qfile(name):
    return os.path.join(QUEUE_DIR, urllib.parse.quote(name, safe="") + ".jsonl")


def load(name):
    try:
        lines = open(qfile(name)).read().splitlines()
    except OSError:
        return []
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def ack(name, after):
    """Drop acknowledged and expired entries (atomic rewrite); returns the entries newer than after."""
    keep = [e for e in load(name) if e["id"] > after and e["t"] >= time.time() - KEEP]
    tmp = qfile(name) + ".tmp"
    with open(tmp, "w") as f:
        f.write("".join(json.dumps(e) + "\n" for e in keep))
    os.replace(tmp, qfile(name))
    return keep


def routed_attachment(name, aid):
    """An attachment of a message still in this rule's queue (only its own conversations)."""
    return any(a.get("id") == aid for e in load(name)
               for a in (((e["msg"].get("envelope") or {}).get("dataMessage") or {}).get("attachments") or []))


def conversation(env):
    gid = ((env.get("dataMessage") or {}).get("groupInfo") or {}).get("groupId")
    return "group." + base64.b64encode(gid.encode()).decode() if gid else env.get("sourceNumber") or env.get("source")


def route(number, msg):
    env = msg.get("envelope") if isinstance(msg, dict) else None
    conv = conversation(env) if isinstance(env, dict) else None
    if not conv:
        return
    for rule in rules():
        if rule.get("admin") or (rule.get("number") == number and can_receive(rule) and conv in (rule.get("recipients") or [])):
            enqueue(rule, number, conv, msg)


def new_id():
    global last_id
    last_id = max(time.time_ns() // 1000, last_id + 1)
    return last_id


def enqueue(rule, number, conv, msg, eid=None):
    name = rule["name"]
    e = {"id": eid or new_id(), "t": int(time.time()), "msg": msg}
    with open(qfile(name), "a") as f:
        f.write(json.dumps(e) + "\n")
    for q in clients.get(name, ()):
        q.put_nowait(e)
    env = msg.get("envelope")  # agent frames have none: no notice
    if isinstance(env, dict) and not clients.get(name) and name not in notified and "dataMessage" in env \
            and (env.get("sourceNumber") or env.get("source")):
        notified.add(name)
        asyncio.create_task(notify(number, conv, rule.get("label") or name))


async def notify(number, conv, label):
    body = json.dumps({"number": number, "recipients": [conv],
                       "message": f"{label} is offline. Your message is queued and arrives when it reconnects."}).encode()
    try:
        ur, uw = await asyncio.open_connection(*UPSTREAM)
        uw.write(b"POST /v2/send HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nConnection: close\r\n"
                 + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        await uw.drain()
        await asyncio.wait_for(ur.read(), 30)
        uw.close()
    except (OSError, asyncio.TimeoutError) as e:
        print(f"notify {label}: {e!r}", flush=True)


async def upstream_ws(number):
    """Keep one websocket to rest-api's receive for number, routing every frame; reconnect forever."""
    while True:
        uw = None
        try:
            ur, uw = await asyncio.open_connection(*UPSTREAM)
            uw.write(f"GET /v1/receive/{number} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
            if b" 101 " not in (await ur.readuntil(b"\r\n\r\n")).split(b"\r\n")[0]:
                raise ConnectionError("no websocket upgrade")
            print(f"upstream connected {number}", flush=True)
            while (m := await ws_read(ur, uw, True)) is not None:
                try:
                    route(number, json.loads(m))
                except ValueError as e:
                    print(f"upstream frame: {e!r}", flush=True)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, OSError) as e:
            print(f"upstream {number}: {e!r}", flush=True)
        if uw:
            uw.close()
        print(f"upstream disconnected {number}, retry in 5 s", flush=True)
        await asyncio.sleep(5)


async def watch():
    ups = set()
    while True:
        for r in rules():
            n = r.get("number")
            if n and not r.get("admin") and can_receive(r) and n not in ups:
                ups.add(n)
                asyncio.create_task(upstream_ws(n))
        await asyncio.sleep(60)


async def serve_client(cr, cw, name, key, after):
    cw.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
              + base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode() + "\r\n\r\n").encode())
    q = asyncio.Queue()  # registered before the replay is read, so nothing falls in between
    clients.setdefault(name, set()).add(q)
    notified.discard(name)

    async def reader():
        try:
            while await ws_read(cr, cw, False) is not None:
                pass
        except (asyncio.IncompleteReadError, ValueError, OSError):
            pass
        q.put_nowait(None)

    task = asyncio.create_task(reader())
    try:
        for e in (ack(name, after) if after is not None else []):
            q.put_nowait(e)
        while (e := await q.get()) is not None:
            ws_send(cw, json.dumps({**e["msg"], "id": e["id"]}).encode())
            await cw.drain()
    finally:
        task.cancel()
        clients[name].discard(q)


# --- agent bus ---
AGENT_BODY, AGENT_TEXT, AGENT_TTL, AGENT_SESSIONS = 64 << 10, 16 << 10, 600, 64
SESSION_CAPS = {"id": 128, "harness": 128, "title": 200, "cwd": 300, "status": 128}
RATE, RATE_WINDOW = 60, 600  # sends per window (s) per sending rule
published = {}  # rule name -> {"updated": epoch, "sessions": [...]}
sends = {}  # rule name -> deque of send times


class TooLarge(Exception):
    pass


def has_agents(rule):
    return bool(rule.get("admin")) or "agents" in (rule.get("allow") or DEFAULT_ALLOW)


def pc_of(rule):
    return rule.get("label") or rule["name"]


def text_field(d, key, n):
    """d[key] as a string cut to n characters (missing/null: ""); anything else is a 400."""
    v = d.get(key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(key)
    return v[:n]


def agent_list():
    old = time.time() - AGENT_TTL
    for n in [n for n, p in published.items() if p["updated"] < old]:
        del published[n]
    return sorted(({"pc": pc_of(r), "online": bool(clients.get(r["name"])), **published[r["name"]]}
                   for r in rules() if has_agents(r) and r["name"] in published), key=lambda p: p["pc"])


def agents(method, path, body, rule):
    """/v1/agents/... for an authenticated rule: (code, reason, JSON body or None)."""
    if not has_agents(rule):
        return 403, "Forbidden", None
    if not QUEUE_DIR:
        return 503, "Service Unavailable", None
    what = path[len("/v1/agents/"):]
    if what not in ("sessions", "send"):
        return 404, "Not Found", None
    if (what, method) not in (("sessions", "GET"), ("sessions", "PUT"), ("send", "POST")):
        return 405, "Method Not Allowed", None
    if method == "GET":
        return 200, "OK", {"pcs": agent_list()}
    name = rule["name"]
    try:
        b = json.loads(body)
        if not isinstance(b, dict):
            raise ValueError("body")
        if what == "sessions":
            ss = b.get("sessions")
            if not isinstance(ss, list) or not all(isinstance(x, dict) for x in ss):
                raise ValueError("sessions")
            if len(ss) > AGENT_SESSIONS:
                raise TooLarge("sessions")
            published[name] = {"updated": int(time.time()),
                               "sessions": [{k: text_field(x, k, n) for k, n in SESSION_CAPS.items()} for x in ss]}
            return 204, "No Content", None
        to, frm, text = b.get("to"), b.get("from") or {}, b.get("text")
        if not isinstance(to, dict) or not isinstance(frm, dict) or not isinstance(text, str) or not text \
                or not isinstance(to.get("pc"), str) or not to["pc"]:
            raise ValueError("fields")
        if len(text.encode()) > AGENT_TEXT:
            raise TooLarge("text")
        dest = {"pc": to["pc"], "session": text_field(to, "session", SESSION_CAPS["id"])}
        src = {"pc": pc_of(rule), "session": text_field(frm, "session", SESSION_CAPS["id"]),
               "title": text_field(frm, "title", SESSION_CAPS["title"])}
    except TooLarge:
        return 413, "Payload Too Large", None
    except ValueError:
        return 400, "Bad Request", None
    target = next((r for r in rules() if has_agents(r) and pc_of(r) == dest["pc"]), None)
    if not target:
        return 404, "Not Found", None
    now, recent = time.time(), sends.setdefault(name, collections.deque())
    while recent and recent[0] <= now - RATE_WINDOW:
        recent.popleft()
    if len(recent) >= RATE:
        return 429, "Too Many Requests", None
    recent.append(now)
    eid = new_id()
    enqueue(target, None, None, {"agent": {"from": src, "to": dest, "text": text, "id": eid}}, eid)
    return 200, "OK", {"id": eid, "online": bool(clients.get(target["name"]))}


async def reply(w, code, text):
    w.write(f"HTTP/1.1 {code} {text}\r\nContent-Type: text/plain\r\nContent-Length: {len(text) + 1}\r\n"
            f"Connection: close\r\n\r\n{text}\n".encode())
    await w.drain()


async def respond(w, code, text, obj):
    if obj is None and code != 204:
        return await reply(w, code, text)
    data = b"" if obj is None else json.dumps(obj).encode()
    w.write(f"HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\n"
            f"Connection: close\r\n\r\n".encode() + data)
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
        if n > (AGENT_BODY if path.startswith("/v1/agents/") else MAX_BODY):
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
            if path.startswith("/v1/agents/"):  # answered here, never forwarded
                code, text, obj = agents(method, path, body, rule)
                print(f"{'ok' if code < 300 else code} {who} {method} {raw}", flush=True)
                return await respond(cw, code, text, obj)
            if not allowed(method, path, body, rule):
                print(f"403 {who} {method} {raw}", flush=True)
                return await reply(cw, 403, "Forbidden")
        upgrade = h.get("upgrade", "").lower() == "websocket" and method == "GET"
        if QUEUE_DIR and method == "GET" and path.startswith("/v1/receive/"):
            q = urllib.parse.parse_qs(target.partition("?")[2])
            after = q.get("after", [""])[0]
            if not upgrade or "sec-websocket-key" not in h or not (after.isdigit() or after == ""):
                return await reply(cw, 400, "Bad Request")
            print(f"ok {who} {method} {raw}", flush=True)
            return await serve_client(cr, cw, who, h["sec-websocket-key"], int(after) if after else None)
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
    if QUEUE_DIR:
        global last_id
        os.makedirs(QUEUE_DIR, exist_ok=True)
        last_id = max([e["id"] for f in os.listdir(QUEUE_DIR) if f.endswith(".jsonl")
                       for e in load(urllib.parse.unquote(f[:-6]))] or [0])
        asyncio.create_task(watch())
    srv = await asyncio.start_server(handle, "0.0.0.0", PORT, limit=65536)
    print(f"listening on {PORT}, upstream {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
