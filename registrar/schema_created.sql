ALTER TABLE reg_elections ADD COLUMN IF NOT EXISTS created timestamptz NOT NULL DEFAULT now();
