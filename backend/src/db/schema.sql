-- TrueMed backend — off-ledger relational schema.
--
-- These three tables hold what the blockchain deliberately does not: the API's
-- own credentials, per-sensor HMAC secrets, and citizen counterfeit reports.
-- They are private, mutable, operational data — the opposite of the public,
-- immutable supply-chain facts on the ledger. Everything secret is stored either
-- as a one-way hash (API keys) or sealed with AES-256-GCM (sensor secrets,
-- reporter contacts), so a dump of this database yields no usable credential and
-- no plaintext personal contact detail.
--
-- Idempotent: safe to run repeatedly (CREATE TABLE IF NOT EXISTS). src/db/migrate.js
-- applies this file; there is no separate migration framework by design — one
-- schema, versioned in git, is enough for a project this size.

-- pgcrypto gives us gen_random_uuid() for primary keys.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── api_keys ──────────────────────────────────────────────────────────────────
-- The API authenticates writers (manufacturer, distributor, sensor, regulator,
-- pharmacy) and dashboard readers (pharma) by an opaque bearer key sent in
-- X-API-Key. Only the SHA-256 hash is stored, so the plaintext key exists only at
-- issue time and on the caller's side; a leaked table cannot be replayed as
-- credentials. Revocation is a timestamp, not a delete, so an audit trail of who
-- could act survives.
--
-- `pharma` and `pharmacy` are different roles and the names are dangerously close
-- (§4.2). `pharma` belongs to a manufacturer and grants read-only analytics over
-- that manufacturer's own batches. `pharmacy` belongs to a retail chemist and
-- grants exactly two custody transitions. Any tool that lists these roles must
-- show what they mean beside the name, not the name alone.
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role         TEXT NOT NULL CHECK (role IN
                   ('manufacturer','distributor','sensor','regulator','pharma','pharmacy')),
    key_hash     TEXT NOT NULL UNIQUE,          -- SHA-256 hex of the bearer key
    label        TEXT NOT NULL DEFAULT '',       -- human note: "Paracip line 3"
    -- What this key may see or act on, empty when the role is not scoped.
    --
    -- For a `pharma` key this is the holder's mfg_licence_no, and it is the only
    -- thing standing between one manufacturer and every competitor's distribution
    -- picture: GET /api/dashboard/pharma filters on it (§4.4a, "a pharma key never
    -- sees another manufacturer's batches"). A pharma key issued with an empty
    -- scope is refused at request time rather than silently shown everything,
    -- because a misconfiguration that fails closed is recoverable and one that
    -- leaks is not.
    scope        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ,                    -- NULL = active
    last_used_at TIMESTAMPTZ
);

-- The CHECK constraint and the scope column both post-date the original table, so
-- a database created before 2026-08-24 needs them added rather than created. Both
-- statements are written to be safe to re-run: ADD COLUMN IF NOT EXISTS is a
-- no-op on a current schema, and the constraint is dropped by name before it is
-- recreated. This is why migrate.js can apply one idempotent file forever instead
-- of accumulating numbered migrations.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT '';
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_role_check;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_role_check CHECK (role IN
    ('manufacturer','distributor','sensor','regulator','pharma','pharmacy'));

-- Auth looks up live keys by hash on every authenticated request; the partial
-- index keeps that lookup to the non-revoked rows only.
CREATE INDEX IF NOT EXISTS api_keys_live_idx
    ON api_keys (key_hash) WHERE revoked_at IS NULL;

-- ── sensors ────────────────────────────────────────────────────────────────────
-- Each ESP32 cold-box sensor shares one HMAC secret with the API, used to
-- authenticate its temperature submissions (§4.5). The secret is sealed with the
-- app encryption key (SecretBox / AES-256-GCM, AAD bound to the sensor id) before
-- it is stored, so secret_enc is ciphertext, never the raw key.
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id   TEXT PRIMARY KEY,               -- e.g. TM-SENS-000042
    secret_enc  BYTEA NOT NULL,                 -- SecretBox-sealed HMAC secret
    label       TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ                      -- NULL = active
);

-- ── counterfeit_reports ─────────────────────────────────────────────────────────
-- One-tap patient reports (§ solution: "with photo, location, pharmacy name").
-- The reporter's contact detail, if given, is sealed (AAD bound to the report id)
-- so the plaintext is never at rest; the photo and coarse lat/lon are stored as
-- submitted. product_id is not a foreign key: a report about a product that is
-- NOT on the ledger is precisely the counterfeit signal we most want to keep.
CREATE TABLE IF NOT EXISTS counterfeit_reports (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    product_id            TEXT NOT NULL,
    pharmacy_name         TEXT NOT NULL DEFAULT '',
    district              TEXT NOT NULL DEFAULT '',
    state                 TEXT NOT NULL DEFAULT '',
    lat                   DOUBLE PRECISION,
    lon                   DOUBLE PRECISION,
    notes                 TEXT NOT NULL DEFAULT '',
    photo                 BYTEA,                 -- optional evidence image
    photo_bytes           INTEGER NOT NULL DEFAULT 0,
    reporter_contact_enc  BYTEA,                 -- SecretBox-sealed, may be NULL
    client_ip             TEXT,
    status                TEXT NOT NULL DEFAULT 'new' CHECK (status IN
                            ('new','triaged','confirmed','dismissed'))
);

-- The CDSCO dashboard queries reports by product and by recency (heat map,
-- newest-first queue), so index both access paths.
CREATE INDEX IF NOT EXISTS reports_product_idx
    ON counterfeit_reports (product_id, created_at DESC);
CREATE INDEX IF NOT EXISTS reports_recent_idx
    ON counterfeit_reports (created_at DESC);
