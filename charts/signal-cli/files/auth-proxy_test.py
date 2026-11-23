#!/usr/bin/env python3
"""Tests for auth-proxy.py against a fake upstream (records requests; 101 + echo for websockets).
Run: python3 -I charts/signal-cli/files/auth-proxy_test.py"""
import asyncio, hashlib, json, os, socket, subprocess, sys, tempfile, threading, time, unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ME, BOT, OTHER = "+48111", "+48222", "+48333"
TOK, ADMIN, NARROW, GRP, DEL = "t0ken", "adm1n", "n4rrow", "gr0up", "d3l"
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


def req(method, path, body=None, token=TOK, extra=b""):
    data = json.dumps(body).encode() if body is not None else b""
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(data)}\r\n"
    if token:
        head += f"Authorization: Bearer {token}\r\n"
    with socket.create_connection(("127.0.0.1", PX), timeout=5) as s:
        s.sendall(head.encode() + b"\r\n" + data + extra)
        out = b""
        while d := s.recv(4096):
            out += d
    return int(out.split(b" ")[1])


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
                                                              "allow": ["send", "read", "groups"]}},
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


if __name__ == "__main__":
    unittest.main(failfast=True)
