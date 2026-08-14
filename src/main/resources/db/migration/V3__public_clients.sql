-- V3__public_clients.sql
-- Add support for PUBLIC OAuth2 clients (browser SPAs: no client secret, PKCE mandatory).
-- Confidential clients keep authenticating with slient_secret_basic.

-- 1. A public client has no secret at all -> NULL must become a legal value.
ALTER TABLE public.client_apps
    ALTER COLUMN client_secret_hash DROP NOT NULL;

-- 2. Record HOW each client authenticates itself.
--    values are the lowercase OAuth spec strings (ClientAuthenticationMethod.getValue());
--    client_secret_basic | client_secret_post | none | private_key_jwt
--    The DEFAULT backfills the existing seeded confidential clients in this same
--    statement (metadata-only on PG 11+, no table rewrite).
ALTER TABLE public.client_apps
    ADD COLUMN client_auth_method varchar(50) NOT NULL DEFAULT 'client_secret_basic';

-- 3. The default was backfill scaffolding only. Removing it means a future code path
--    forgets to set the method fails loud instead of looking deliberately confidential.
ALTER TABLE public.client_apps
    ALTER COLUMN client_auth_method DROP DEFAULT;
