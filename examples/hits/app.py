"""A web page that counts its visitors in Redis.

The example of docs/learn/18-building-images.md (its Containerfile) and
19-compose.md (its compose.yaml): `rustlet compose up -d`, then
`curl localhost:8000`.
"""

import http.server
import os

import redis

store = redis.Redis(host=os.environ.get("REDIS_HOST", "redis"), port=6379, socket_timeout=2)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path == "/health":
                store.ping()
                return self.reply(200, "ok\n")
            hits = store.incr("hits")
        except redis.RedisError as e:
            return self.reply(503, f"redis: {e}\n")
        self.reply(200, f"Hello from Rustlets! I have been seen {hits} times.\n")

    def reply(self, status, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"{self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"serving on :{port}", flush=True)
    http.server.ThreadingHTTPServer(("", port), Handler).serve_forever()
