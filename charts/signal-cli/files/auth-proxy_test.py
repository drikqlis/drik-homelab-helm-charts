#!/usr/bin/env python3
"""Tests for auth-proxy.py against a fake upstream (records requests; 101 + echo for websockets).
Run: python3 -I charts/signal-cli/files/auth-proxy_test.py"""
import asyncio, base64, hashlib, importlib.util, json, os, socket, subprocess, sys, tempfile, threading, time, unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ME, BOT, OTHER = "+48111", "+48222", "+48333"
TOK, ADMIN, NARROW, GRP, DEL, AGT = "t0ken", "adm1n", "n4rrow", "gr0up", "d3l", "4gt"
G = "group.abc="
seen = []  # request heads+bodies the upstream got


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


UP, PX = free_port(), free_port()


async def upstream(r, w):
    head = await r.readuntil(b"\r\n\r\n")
    n = next((int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")), 0)
    body = await r.readexactly(n)
    seen.append(head + body)
    if b"upgrade: websocket" in head.lower():
        w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        while d := await r.read(100):
            w.write(b"echo:" + d)
            await w.drain()
    else:
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    await w.drain()
    w.close()


def run_upstream():
    async def main():
        async with await asyncio.start_server(upstream, "127.0.0.1", UP) as s:
            await s.serve_forever()
    asyncio.run(main())


def http(port, method, path, body=None, token=TOK, extra=b"", raw=None):
    """(status, response body) for one request; raw: send these body bytes instead of JSON."""
    data = raw if raw is not None else json.dumps(body).encode() if body is not None else b""
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n"
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(head.encode() + b"\r\n" + data + extra)
        out = b""
        try:
            while d := s.recv(65536):
                out += d
        except ConnectionResetError:  # proxy answered before reading an oversized body
            pass
    return int(out.split(b" ")[1]), out.partition(b"\r\n\r\n")[2]


def req(method, path, body=None, token=TOK, extra=b""):
    return http(PX, method, path, body, token, extra)[0]


class Proxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        threading.Thread(target=run_upstream, daemon=True).start()
        cls.tokens = os.path.join(tempfile.mkdtemp(), "tokens.json")
        json.dump({hashlib.sha256(TOK.encode()).hexdigest(): {"name": "claude", "number": BOT, "recipients": [ME]},
                   hashlib.sha256(ADMIN.encode()).hexdigest(): {"name": "admin", "admin": True},
                   hashlib.sha256(NARROW.encode()).hexdigest(): {"name": "dagonite", "number": BOT, "recipients": [ME],
                                                                 "allow": ["send"]},
                   hashlib.sha256(DEL.encode()).hexdigest(): {"name": "del", "number": BOT, "recipients": [ME],
                                                              "allow": ["send", "delete"]},
                   hashlib.sha256(GRP.encode()).hexdigest(): {"name": "grp", "number": BOT, "recipients": [G],
                                                              "allow": ["send", "read", "groups"]},
                   hashlib.sha256(AGT.encode()).hexdigest(): {"name": "agt", "number": BOT, "recipients": [],
                                                              "allow": ["agents"]}},
                  open(cls.tokens, "w"))
        cls.p = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "auth-proxy.py")],
                                 env=dict(os.environ, PORT=str(PX), UPSTREAM_PORT=str(UP), TOKENS_FILE=cls.tokens),
                                 stdout=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PX)).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.p.kill()

    def setUp(self):
        seen.clear()

    def send(self, **kw):
        return req("POST", "/v2/send", {"number": BOT, "recipients": [ME], "message": "hi", **kw})

    def test_send_to_me_ok_and_token_not_forwarded(self):
        self.assertEqual(self.send(), 200)
        self.assertNotIn(b"t0ken", seen[0])
        self.assertIn(b"Connection: close", seen[0])

    def test_send_to_other_or_group_denied(self):
        self.assertEqual(self.send(recipients=[ME, OTHER]), 403)
        self.assertEqual(self.send(recipients=["group.abc"]), 403)
        self.assertEqual(self.send(recipients=[]), 403)
        self.assertEqual(self.send(number=OTHER), 403)
        self.assertEqual(seen, [])

    def test_no_or_wrong_token(self):
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": [ME]}, token=None), 401)
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": [ME]}, token="nope"), 401)

    def test_health_open(self):
        self.assertEqual(req("GET", "/v1/health", token=None), 200)

    def test_reactions(self):
        self.assertEqual(req("POST", f"/v1/reactions/{BOT}", {"recipient": ME, "reaction": "x"}), 200)
        self.assertEqual(req("POST", f"/v1/reactions/{BOT}", {"recipient": OTHER, "reaction": "x"}), 403)
        self.assertEqual(req("POST", "/v1/reactions/%2B48222", {"recipient": ME, "reaction": "x"}), 200)

    def test_account_endpoints_denied(self):
        for m, p in [("GET", f"/v1/groups/{BOT}"), ("POST", f"/v1/groups/{BOT}/g/quit"), ("GET", "/v1/accounts"),
                     ("POST", f"/v1/accounts/{BOT}/pin"), ("POST", f"/v1/register/{BOT}"), ("GET", f"/v1/receive/{OTHER}"),
                     ("POST", "/v2/send/../../v1/accounts"), ("POST", "//v2/send")]:
            self.assertIn(req(m, p, {"number": BOT, "recipients": [ME]}), (400, 403), p)
        self.assertEqual(seen, [])

    def test_smuggled_second_request_not_forwarded(self):
        extra = b"POST /v1/groups/x/quit HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
        data = json.dumps({"number": BOT, "recipients": [ME]}).encode()
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": [ME]}, extra=extra), 200)
        time.sleep(0.2)
        self.assertEqual(len(seen), 1)
        self.assertNotIn(b"quit", seen[0])

    def test_duplicate_length_and_chunked_rejected(self):
        with socket.create_connection(("127.0.0.1", PX), timeout=5) as s:
            s.sendall(f"POST /v2/send HTTP/1.1\r\nAuthorization: Bearer {TOK}\r\nContent-Length: 2\r\n"
                      "Content-Length: 40\r\n\r\n{}".encode())
            self.assertIn(b" 400 ", s.recv(100))
        with socket.create_connection(("127.0.0.1", PX), timeout=5) as s:
            s.sendall(f"POST /v2/send HTTP/1.1\r\nAuthorization: Bearer {TOK}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode())
            self.assertIn(b" 400 ", s.recv(100))

    def test_admin_passes_everything(self):
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/g/quit", {}, token=ADMIN), 200)

    def test_allow_send_only(self):
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": [ME]}, token=NARROW), 200)
        self.assertEqual(req("POST", f"/v1/reactions/{BOT}", {"recipient": ME}, token=NARROW), 403)
        self.assertEqual(req("GET", f"/v1/receive/{BOT}", token=NARROW), 403)
        self.assertEqual(req("GET", f"/v1/contacts/{BOT}", token=NARROW), 403)

    def test_default_allow_has_no_read_or_groups(self):
        self.assertEqual(req("GET", f"/v1/groups/{BOT}"), 403)
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/{G}/join", {}), 403)
        self.assertEqual(req("DELETE", f"/v1/reactions/{BOT}", {"recipient": ME}), 200)

    def test_delete_only_when_allowed(self):
        body = {"recipient": ME, "timestamp": 1}
        self.assertEqual(req("DELETE", f"/v1/remote-delete/{BOT}", body), 403)  # default allow: no delete
        self.assertEqual(req("DELETE", f"/v1/remote-delete/{BOT}", body, token=DEL), 200)
        self.assertEqual(req("DELETE", f"/v1/remote-delete/{BOT}", {"recipient": OTHER, "timestamp": 1}, token=DEL), 403)
        self.assertEqual(req("DELETE", f"/v1/remote-delete/{OTHER}", body, token=DEL), 403)

    def test_listed_group(self):
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": [G]}, token=GRP), 200)
        self.assertEqual(req("POST", "/v2/send", {"number": BOT, "recipients": ["group.other"]}, token=GRP), 403)
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/{G}/join", {}, token=GRP), 200)
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/{G}/quit", {}, token=GRP), 200)
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/group.other/join", {}, token=GRP), 403)
        self.assertEqual(req("POST", f"/v1/groups/{BOT}/{G}/members", {}, token=GRP), 403)
        self.assertEqual(req("POST", f"/v1/groups/{OTHER}/{G}/join", {}, token=GRP), 403)

    def test_read(self):
        for p in (f"/v1/contacts/{BOT}", f"/v1/groups/{BOT}", f"/v1/groups/{BOT}/{G}"):
            self.assertEqual(req("GET", p, token=GRP), 200, p)
        for p in (f"/v1/groups/{OTHER}", f"/v1/groups/{BOT}/{G}/x", f"/v1/accounts/{BOT}", f"/v1/contacts/{BOT}/x/y"):
            self.assertEqual(req("GET", p, token=GRP), 403, p)

    def test_websocket_receive(self):
        with socket.create_connection(("127.0.0.1", PX), timeout=5) as s:
            s.sendall(f"GET /v1/receive/{BOT} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Authorization: Bearer {TOK}\r\n\r\n".encode())
            self.assertIn(b" 101 ", s.recv(200))
            s.sendall(b"ping")
            self.assertEqual(s.recv(100), b"echo:ping")
        self.assertIn(b"Connection: Upgrade", seen[0])

    def test_agents_need_router_mode_and_permission(self):
        self.assertEqual(req("GET", "/v1/agents/sessions", token=AGT), 503)
        self.assertEqual(req("GET", "/v1/agents/sessions"), 403)  # no agents in allow
        self.assertEqual(req("POST", "/v1/agents/send", {"to": {"pc": "x"}, "text": "t"}), 403)
        self.assertEqual(seen, [])  # never forwarded


# --- router mode: fake rest-api that pushes receive frames and records POST /v2/send ---
RUP, RPX = free_port(), free_port()
RA, RB, RC, RN = "t-ra", "t-rb", "t-rc", "t-rn"
AX, AY, AS = "t-ax", "t-ay", "t-as"  # agent bus: PCs mk-x870, mm-b850, "as" (no label: name)
sent, subs, loop_box = [], [], []  # recorded notices, websocket writers attached, the fake's event loop
GID = "int-group-id"
PUB = "group." + base64.b64encode(GID.encode()).decode()
C = "+48444"


def wsframe(data, op=1, fin=True, mask=False):
    n, m = len(data), 128 if mask else 0
    head = bytes([(128 if fin else 0) | op]) + (bytes([m | n]) if n < 126 else bytes([m | 126]) + n.to_bytes(2, "big"))
    if mask:
        return head + b"\0\0\0\0" + data  # zero key: payload unchanged
    return head + data


def push(msg, fragments=1):
    """Have the fake upstream send msg to every attached subscriber (as `fragments` text frames)."""
    raw = json.dumps(msg).encode()
    k = -(-len(raw) // fragments)
    parts = [raw[i:i + k] for i in range(0, len(raw), k)]
    out = b"".join(wsframe(x, 1 if i == 0 else 0, i == len(parts) - 1) for i, x in enumerate(parts))
    loop_box[0].call_soon_threadsafe(lambda: [w.write(out) for w in subs])


def dm(src, text="hi"):
    return {"envelope": {"sourceNumber": src, "dataMessage": {"message": text}}, "account": BOT}


def grp(text="g"):
    return {"envelope": {"sourceNumber": ME, "dataMessage": {"message": text, "groupInfo": {"groupId": GID}}},
            "account": BOT}


async def router_upstream(r, w):
    head = await r.readuntil(b"\r\n\r\n")
    if head.startswith(b"GET /v1/attachments/"):
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nIMG")
    elif head.startswith(b"POST /v2/send"):
        n = next(int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:"))
        sent.append(json.loads(await r.readexactly(n)))
        w.write(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    else:
        w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        w.write(wsframe(b"x", 9))  # ping: the proxy must pong with a masked frame
        subs.append(w)
        await r.read()
        subs.remove(w)
    await w.drain()
    w.close()


def run_router_upstream():
    async def main():
        loop_box.append(asyncio.get_running_loop())
        async with await asyncio.start_server(router_upstream, "127.0.0.1", RUP) as s:
            await s.serve_forever()
    asyncio.run(main())


def wait_for(cond, what="condition"):
    for _ in range(50):
        if cond():
            return
        time.sleep(0.1)
    raise AssertionError("timeout waiting for " + what)


class WS:
    """Websocket client for the proxy (frames masked with a zero key)."""
    def __init__(self, token, number=BOT, query="", expect=b" 101 "):
        self.s = socket.create_connection(("127.0.0.1", RPX), timeout=5)
        self.s.sendall(f"GET /v1/receive/{number}{query} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                       f"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       f"Authorization: Bearer {token}\r\n\r\n".encode())
        self.buf = b""
        head = self.read(None).decode()
        self.status, self.hdrs = head.split("\r\n", 1)[0].encode(), head.encode()

    def read(self, n):
        """n bytes, or everything up to the end of the HTTP head when n is None."""
        while (n is None and b"\r\n\r\n" not in self.buf) or (n is not None and len(self.buf) < n):
            d = self.s.recv(4096)
            if not d:
                raise ValueError("closed")
            self.buf += d
        k = self.buf.index(b"\r\n\r\n") + 4 if n is None else n
        out, self.buf = self.buf[:k], self.buf[k:]
        return out

    def recv(self, timeout=3):
        """(op, payload) of the next frame, None when nothing arrives in time."""
        self.s.settimeout(timeout)
        try:
            b1, b2 = self.read(2)
            n = b2 & 127
            if n == 126:
                n = int.from_bytes(self.read(2), "big")
            return b1 & 15, self.read(n)
        except (socket.timeout, ValueError):
            return None

    def msg(self, timeout=3):
        f = self.recv(timeout)
        return json.loads(f[1]) if f and f[0] == 1 else f

    def close(self):
        self.s.close()


class Router(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        threading.Thread(target=run_router_upstream, daemon=True).start()
        cls.dir = tempfile.mkdtemp()
        cls.tokens = os.path.join(cls.dir, "tokens.json")
        rule = lambda n, rc, **kw: {"name": n, "number": BOT, "recipients": rc, **kw}
        json.dump({hashlib.sha256(t.encode()).hexdigest(): r for t, r in [
            (RA, rule("ra", [ME, PUB], allow=["send", "react", "receive", "attachments"])), (RB, rule("rb", [OTHER], label="Box")), (RC, rule("rc", [C])),
            (RN, rule("rn", [ME], allow=["send"])), (ADMIN, {"name": "admin", "admin": True}),
            (AX, rule("ax", [], label="mk-x870", allow=["send", "receive", "agents"])),
            (AY, rule("ay", [], label="mm-b850", allow=["receive", "agents", "attachments"])),
            (AS, rule("as", [], allow=["agents"]))]},
                  open(cls.tokens, "w"))
        cls.q = os.path.join(cls.dir, "queue")
        cls.p = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "auth-proxy.py")],
                                 env=dict(os.environ, PORT=str(RPX), UPSTREAM_PORT=str(RUP), TOKENS_FILE=cls.tokens,
                                          QUEUE_DIR=cls.q), stdout=subprocess.DEVNULL)
        wait_for(lambda: loop_box and subs, "proxy to attach upstream")

    @classmethod
    def tearDownClass(cls):
        cls.p.kill()

    def setUp(self):
        sent.clear()
        for f in os.listdir(self.q) if os.path.isdir(self.q) else ():
            os.remove(os.path.join(self.q, f))

    def queued(self, name):
        try:
            with open(os.path.join(self.q, name + ".jsonl")) as f:
                return [json.loads(l) for l in f]
        except OSError:
            return []

    def test_routing_group_dm_and_unlisted(self):
        push(grp("in group"))
        push(dm(ME, "dm"))
        push(dm(OTHER, "other"))
        push(dm("+48999", "stranger"))
        push({"envelope": {"typingMessage": {}}, "account": BOT})  # no conversation: dropped
        wait_for(lambda: len(self.queued("ra")) == 2 and self.queued("rb"), "routing")
        time.sleep(0.3)
        self.assertEqual([e["msg"]["envelope"]["dataMessage"]["message"] for e in self.queued("ra")], ["in group", "dm"])
        self.assertEqual([e["msg"]["envelope"]["dataMessage"]["message"] for e in self.queued("rb")], ["other"])
        self.assertEqual(self.queued("rc"), [])
        self.assertEqual(self.queued("rn"), [])  # allow has no receive
        a, b = self.queued("ra"), self.queued("rb")
        self.assertLess(a[0]["id"], a[1]["id"])
        self.assertLess(a[1]["id"], b[0]["id"])
        self.assertEqual(len(self.queued("admin")), 5 - 1)  # admin gets everything that has a conversation

    def test_fragmented_long_frame_queued(self):
        push(dm(ME, "x" * 300), fragments=3)
        wait_for(lambda: self.queued("ra"), "fragmented frame")
        self.assertEqual(self.queued("ra")[0]["msg"]["envelope"]["dataMessage"]["message"], "x" * 300)

    def test_replay_after_and_trim_then_live(self):
        for i in range(3):
            push(dm(ME, f"m{i}"))
        wait_for(lambda: len(self.queued("ra")) == 3, "queue")
        ids = [e["id"] for e in self.queued("ra")]
        c = WS(RA, query=f"?after={ids[0]}")
        self.assertIn(b" 101 ", c.status)
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", c.hdrs)
        got = [c.msg() for _ in range(2)]
        self.assertEqual([m["id"] for m in got], ids[1:])
        self.assertEqual(got[0]["envelope"]["dataMessage"]["message"], "m1")
        self.assertEqual(got[0]["account"], BOT)
        self.assertEqual([e["id"] for e in self.queued("ra")], ids[1:])  # acked entry trimmed
        self.assertIsNone(c.recv(0.5))
        push(dm(ME, "live"))
        live = c.msg()
        self.assertEqual(live["envelope"]["dataMessage"]["message"], "live")
        self.assertGreater(live["id"], ids[-1])
        c.s.sendall(wsframe(b"p", 9, mask=True))
        self.assertEqual(c.recv(), (10, b"p"))
        c.close()

    def test_no_replay_without_after(self):
        push(dm(ME, "old"))
        wait_for(lambda: self.queued("ra"), "queue")
        c = WS(RA)
        self.assertIsNone(c.recv(0.5))
        self.assertEqual(len(self.queued("ra")), 1)  # nothing trimmed
        push(dm(ME, "new"))
        self.assertEqual(c.msg()["envelope"]["dataMessage"]["message"], "new")
        c.close()

    def test_old_entries_dropped_on_rewrite(self):
        os.makedirs(self.q, exist_ok=True)
        with open(os.path.join(self.q, "ra.jsonl"), "w") as f:
            f.write(json.dumps({"id": 1, "t": 1, "msg": dm(ME, "ancient")}) + "\n")
        c = WS(RA, query="?after=0")
        self.assertIsNone(c.recv(0.5))
        self.assertEqual(self.queued("ra"), [])
        c.close()

    def test_offline_notice_once_then_reset_by_connect(self):
        push(dm(C, "one"))
        push(dm(C, "two"))
        wait_for(lambda: sent, "notice")
        time.sleep(0.3)
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["number"], BOT)
        self.assertEqual(sent[0]["recipients"], [C])
        self.assertIn("rc is offline", sent[0]["message"])
        c = WS(RC)
        c.close()
        time.sleep(0.3)
        sent.clear()
        push(dm(C, "three"))
        wait_for(lambda: sent, "second notice after reconnect")
        self.assertEqual(len(sent), 1)

    def test_notice_uses_label_and_skips_online_and_non_messages(self):
        c = WS(RB)
        push(dm(OTHER, "online"))
        self.assertEqual(c.msg()["envelope"]["dataMessage"]["message"], "online")
        time.sleep(0.3)
        self.assertEqual(sent, [])
        c.close()
        time.sleep(0.3)
        push({"envelope": {"sourceNumber": OTHER, "typingMessage": {}}, "account": BOT})  # not a dataMessage
        time.sleep(0.3)
        self.assertEqual(sent, [])
        push(dm(OTHER, "offline"))
        wait_for(lambda: sent, "notice")
        self.assertEqual(sent[0]["message"], "Box is offline. Your message is queued and arrives when it reconnects.")

    def test_attachments_only_from_own_queue(self):
        m = grp("pic")
        m["envelope"]["dataMessage"]["attachments"] = [{"id": "abc.jpg", "contentType": "image/jpeg"}]
        push(m)
        wait_for(lambda: self.queued("ra"), "queued")
        for tok, aid, want in [(RA, "abc.jpg", b" 200 "), (RA, "other.jpg", b" 403 "), (RB, "abc.jpg", b" 403 ")]:
            with socket.create_connection(("127.0.0.1", RPX), timeout=5) as s:
                s.sendall(f"GET /v1/attachments/{aid} HTTP/1.1\r\nAuthorization: Bearer {tok}\r\n\r\n".encode())
                self.assertIn(want, s.recv(100), (tok, aid))

    def test_client_checks(self):
        self.assertIn(b" 403 ", WS(RN, query="").status)  # allow without receive
        self.assertIn(b" 403 ", WS(RA, number=OTHER).status)
        self.assertIn(b" 401 ", WS("nope").status)
        self.assertIn(b" 400 ", WS(RA, query="?after=x").status)
        with socket.create_connection(("127.0.0.1", RPX), timeout=5) as s:  # plain GET, no upgrade
            s.sendall(f"GET /v1/receive/{BOT} HTTP/1.1\r\nAuthorization: Bearer {RA}\r\n\r\n".encode())
            self.assertIn(b" 400 ", s.recv(100))

    # --- agent bus ---
    def api(self, method, path, body=None, token=AX, raw=None):
        code, out = http(RPX, method, path, body, token, raw=raw)
        return code, json.loads(out) if out.startswith(b"{") else None

    def agent_send(self, to="mm-b850", text="hello", token=AX, **kw):
        return self.api("POST", "/v1/agents/send", {"to": {"pc": to, "session": "s2"},
                                                    "from": {"session": "s1", "title": "fixing"}, "text": text, **kw},
                        token)

    def test_agents_permission(self):
        for tok in (RA, RN):  # no agents in allow
            self.assertEqual(self.api("GET", "/v1/agents/sessions", token=tok)[0], 403)
            self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": []}, token=tok)[0], 403)
            self.assertEqual(self.agent_send(token=tok)[0], 403)
        self.assertEqual(self.api("GET", "/v1/agents/sessions", token="nope")[0], 401)
        self.assertEqual(self.queued("ay"), [])

    def test_agents_publish_and_list(self):
        sessions = [{"id": "s1", "harness": "claude", "title": "t" * 300, "cwd": None, "status": "busy", "x": 1},
                    {"id": "s2", "harness": "codex", "title": "two", "cwd": "/home/u/" + "d" * 400, "status": "idle"}]
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": sessions}), (204, None))
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": []}, token=AY), (204, None))
        code, out = self.api("GET", "/v1/agents/sessions", token=AY)
        self.assertEqual(code, 200)
        pcs = {p["pc"]: p for p in out["pcs"]}
        self.assertNotIn("ra", pcs)
        self.assertNotIn("Box", pcs)
        x = pcs["mk-x870"]
        self.assertFalse(x["online"])
        self.assertLessEqual(abs(x["updated"] - time.time()), 5)
        self.assertEqual(x["sessions"][0], {"id": "s1", "harness": "claude", "title": "t" * 200, "cwd": "",
                                            "status": "busy"})
        self.assertEqual(len(x["sessions"][1]["cwd"]), 300)
        self.assertEqual(pcs["mm-b850"]["sessions"], [])
        c = WS(AX)
        self.assertTrue({p["pc"]: p for p in self.api("GET", "/v1/agents/sessions")[1]["pcs"]}["mk-x870"]["online"])
        c.close()
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": sessions[1:]}), (204, None))  # replaces
        self.assertEqual([s["id"] for s in {p["pc"]: p for p in self.api("GET", "/v1/agents/sessions")[1]["pcs"]}
                          ["mk-x870"]["sessions"]], ["s2"])

    def test_agents_send_online_and_no_spoofing(self):
        c = WS(AY)
        code, out = self.agent_send(**{"from": {"pc": "evil", "session": "s1", "title": "fixing"}})
        self.assertEqual(code, 200)
        self.assertTrue(out["online"])
        want = {"agent": {"from": {"pc": "mk-x870", "session": "s1", "title": "fixing"},
                          "to": {"pc": "mm-b850", "session": "s2"}, "text": "hello", "id": out["id"]}, "id": out["id"]}
        self.assertEqual(c.msg(), want)
        c.close()
        self.assertEqual([e["id"] for e in self.queued("ay")], [out["id"]])
        self.assertEqual(self.queued("ax"), [])
        time.sleep(0.3)
        self.assertEqual(sent, [])

    def test_agents_send_offline_queued_and_replayed(self):
        code, out = self.agent_send(text="while away")
        self.assertEqual(code, 200)
        self.assertFalse(out["online"])
        time.sleep(0.3)
        self.assertEqual(sent, [])  # no offline notice for agent frames
        self.assertEqual(self.queued("ay")[0]["msg"]["agent"]["text"], "while away")
        c = WS(AY, query="?after=0")
        got = c.msg()
        self.assertEqual((got["id"], got["agent"]["id"], got["agent"]["text"]), (out["id"], out["id"], "while away"))
        live = self.agent_send(text="now")[1]
        self.assertTrue(live["online"])
        self.assertGreater(live["id"], out["id"])
        self.assertEqual(c.msg()["agent"]["text"], "now")
        c.close()
        c = WS(AY, query=f"?after={live['id']}")  # acknowledged: nothing replayed
        self.assertIsNone(c.recv(0.5))
        c.close()
        self.assertEqual(self.queued("ay"), [])

    def test_agents_send_to_own_pc(self):
        code, out = self.agent_send(to="mk-x870")
        self.assertEqual(code, 200)
        self.assertEqual(self.queued("ax")[0]["msg"]["agent"]["from"]["pc"], "mk-x870")

    def test_agents_errors(self):
        self.assertEqual(self.agent_send(to="nowhere")[0], 404)
        self.assertEqual(self.agent_send(to="ra")[0], 404)  # exists, but no agents
        self.assertEqual(self.agent_send(to="Box")[0], 404)
        self.assertEqual(self.api("GET", "/v1/agents/nope")[0], 404)
        self.assertEqual(self.api("GET", "/v1/agents/send")[0], 405)
        self.assertEqual(self.api("POST", "/v1/agents/sessions", {"sessions": []})[0], 405)
        for b in ({"to": {"pc": "mm-b850"}}, {"to": "mm-b850", "text": "x"}, {"to": {"pc": ""}, "text": "x"},
                  {"to": {"pc": "mm-b850", "session": 5}, "text": "x"}, {"to": {"pc": "mm-b850"}, "text": ""}, [1]):
            self.assertEqual(self.api("POST", "/v1/agents/send", b)[0], 400, b)
        self.assertEqual(self.api("POST", "/v1/agents/send", raw=b"{nope")[0], 400)
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": "x"})[0], 400)
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": [{"id": 1}]})[0], 400)
        self.assertEqual(self.agent_send(text="x" * (16 << 10))[0], 200)
        self.assertEqual(self.agent_send(text="x" * ((16 << 10) + 1))[0], 413)
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", {"sessions": [{"id": "s"}] * 65})[0], 413)
        self.assertEqual(self.api("PUT", "/v1/agents/sessions", raw=b" " * ((64 << 10) + 1))[0], 413)
        self.assertEqual(len(self.queued("ay")), 1)  # only the 16 KB one

    def test_agents_rate_limit(self):
        for i in range(60):
            self.assertEqual(self.agent_send(to="as", token=AS)[0], 200, i)
        self.assertEqual(self.agent_send(to="as", token=AS)[0], 429)
        self.assertEqual(len(self.queued("as")), 60)
        self.assertEqual(self.agent_send(to="as")[0], 200)  # per sending rule

    def test_agent_frames_dont_break_existing_paths(self):
        self.assertEqual(self.agent_send()[0], 200)
        with socket.create_connection(("127.0.0.1", RPX), timeout=5) as s:  # attachment lookup scans the queue
            s.sendall(f"GET /v1/attachments/abc.jpg HTTP/1.1\r\nAuthorization: Bearer {AY}\r\n\r\n".encode())
            self.assertIn(b" 403 ", s.recv(100))
        push(dm(ME, "after agent"))
        wait_for(lambda: self.queued("ra"), "routing still works")
        self.assertIsNone(self.p.poll())


class AgentList(unittest.TestCase):
    """agent_list() in-process: stale lists are dropped."""
    def test_stale_dropped(self):
        spec = importlib.util.spec_from_file_location("proxy", os.path.join(HERE, "auth-proxy.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.TOKENS_FILE = os.path.join(tempfile.mkdtemp(), "tokens.json")
        json.dump({"a": {"name": "a", "label": "pc-a", "allow": ["agents"]}, "b": {"name": "b", "allow": ["agents"]},
                   "c": {"name": "c", "allow": ["send"]}}, f := open(m.TOKENS_FILE, "w"))
        f.close()
        now = int(time.time())
        m.published.update(a={"updated": now - 30, "sessions": []}, b={"updated": now - 601, "sessions": []},
                           c={"updated": now, "sessions": []})
        self.assertEqual(m.agent_list(), [{"pc": "pc-a", "online": False, "updated": now - 30, "sessions": []}])
        self.assertNotIn("b", m.published)


if __name__ == "__main__":
    unittest.main(failfast=True)
