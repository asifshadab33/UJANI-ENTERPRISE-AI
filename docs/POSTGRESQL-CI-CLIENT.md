# PostgreSQL CI client

The customer-hosted database integration job uses the PostgreSQL 16 service
container as both server and client. The official `postgres:16` image includes
`psql`, so the runner does not need to install a second client package from an
external Ubuntu mirror.

The workflow creates a small runner-side wrapper that invokes `psql` through
`docker exec`. It forwards the test password and `PGAPPNAME`, which is used by
the two-session telemetry serialization regression. SQL files are still checked
out and passed to `psql` through standard input; the database version and
`ON_ERROR_STOP` behavior are unchanged.
