-- Tabella utenti CryptoTrade Pro
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  full_name TEXT DEFAULT '',
  passkey_hash TEXT NOT NULL,
  password_hash TEXT DEFAULT '',
  device_fingerprints JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_login TIMESTAMPTZ
);

-- Abilita RLS
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Policy: solo service_role può leggere/scrivere (le Edge Functions usano service_role)
CREATE POLICY "service_role_only" ON public.users
  USING (auth.role() = 'service_role');

-- Index per email lookup veloce
CREATE INDEX IF NOT EXISTS users_email_idx ON public.users(email);
