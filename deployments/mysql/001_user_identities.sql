-- 001_user_identities.sql — multi-provider OAuth account model.
-- The legacy "user" table is untouched: Google logins keep double-writing
-- google_id/oidc_token/picture there so /me googleId and the offer frame
-- stay byte-compatible.
--
-- Deployment order: run this file BEFORE deploying the new
-- image — the backfill below guarantees existing Google users hit the
-- (provider, provider_user_id) lookup on their first post-deploy login.
--
-- PRECHECK: the legacy upsert matched on (google_id AND email), so one
-- Google sub can in theory exist on several user rows. Duplicates would
-- violate uk_provider_uid during backfill. Resolve manually first:
--   SELECT google_id, COUNT(*) AS n, GROUP_CONCAT(id) AS user_ids
--   FROM user WHERE google_id IS NOT NULL
--   GROUP BY google_id HAVING n > 1;
-- (keep the row that owns devices, re-point the others' references, or
--  accept the INSERT IGNORE drop list below)
-- The follow-up SELECT lists identities that were skipped, if any.

CREATE TABLE IF NOT EXISTS user_identities (
  id INT(11) NOT NULL AUTO_INCREMENT,
  user_id INT(11) NOT NULL,
  provider VARCHAR(32) NOT NULL,           -- google | microsoft | github | wechat
  provider_user_id VARCHAR(191) NOT NULL,  -- google/microsoft: sub; github: numeric id; wechat: unionid (fallback openid)
  email VARCHAR(255) DEFAULT NULL,
  display_name VARCHAR(255) DEFAULT NULL,
  avatar_url VARCHAR(1024) DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_provider_uid (provider, provider_user_id),
  KEY idx_identities_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Backfill from existing Google users (idempotent via INSERT IGNORE).
INSERT IGNORE INTO user_identities (user_id, provider, provider_user_id, email)
SELECT id, 'google', google_id, email FROM user WHERE google_id IS NOT NULL;

-- Post-check: rows skipped by IGNORE (duplicate google_id), must be empty
-- or resolved by hand.
SELECT u.id, u.google_id, u.email
FROM user u
WHERE u.google_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM user_identities ui
    WHERE ui.provider = 'google' AND ui.provider_user_id = u.google_id
  );
