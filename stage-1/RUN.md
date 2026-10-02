# Pocketful stage 1

Dependency-free Node.js 22 HTTP service with in-memory state.

Build and start (listens on `$PORT`, default 8080):

```sh
docker build -t pocketful-s1 . && docker run --rm -e PORT=8080 -p 8080:8080 pocketful-s1
```

Without Docker: `PORT=8080 node server.js`.

Seed state with `POST /_test/reset` (fixture JSON), snapshot with `GET /_test/export`,
restore with `POST /_test/import`. State lives in memory and does not survive a restart.
