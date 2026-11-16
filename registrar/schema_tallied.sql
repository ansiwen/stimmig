ALTER TABLE reg_elections ADD COLUMN IF NOT EXISTS tallied boolean NOT NULL DEFAULT false;
