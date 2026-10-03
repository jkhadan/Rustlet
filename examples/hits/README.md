# hits

A web page that counts its visitors in Redis: the example of
[chapter 18](../../docs/learn/18-building-images.md) (building an image) and
[chapter 19](../../docs/learn/19-compose.md) (running it with compose).

```sh
rustlet compose up -d          # builds hits-web, pulls redis:7-alpine, starts redis, waits for it to be healthy, starts web
curl localhost:8000            # Hello from Rustlets! I have been seen 1 times.
curl localhost:8000            # … 2 times.
rustlet compose ps
rustlet compose logs web
rustlet compose down           # -v also removes the data volume
```

Or build the image on its own: `rustlet build -t hits-web .`
