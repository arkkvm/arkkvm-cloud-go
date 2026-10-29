-- 002_mcp_tokens.sql — first-class credentials for the arkkvm_mcp host tool.
-- Replaces the web-session-token capture: the MCP tool now
-- exchanges a one-time grant code (Redis ARK:AUTH:MCPCODE, minted by the
-- OAuth callback when the authorize flow carries client=mcp) for a dedicated
-- long-lived token, so MCP and browser sessions stop evicting each other
-- (single-session model) and the credential power shrinks to a fixed
-- allowlist (device list/read + ICE + signaling).
--
-- Only the SHA-256 of each token is stored; the plaintext is returned exactly
-- once by POST /mcp/token and lives in the tool's 0600 token file. Tokens do
-- not expire on their own — revocation is explicit (revoked_at) via
-- POST /mcp/revoke; last_used_at is the staleness/audit marker.
--
-- Deployment order: run BEFORE deploying the image that wires McpTokenRepo.
-- Until then only the new MCP endpoints fail; every existing flow is
-- unaffected. No backfill needed (no legacy MCP credentials exist).

CREATE TABLE IF NOT EXISTS mcp_tokens (
  id INT(11) NOT NULL AUTO_INCREMENT,
  user_id INT(11) NOT NULL,
  token_hash CHAR(64) NOT NULL,            -- sha256 hex of the bearer token
  name VARCHAR(64) NOT NULL DEFAULT 'mcp', -- free-form label (management UI later)
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_used_at DATETIME DEFAULT NULL,
  revoked_at DATETIME DEFAULT NULL,        -- NULL = active
  PRIMARY KEY (id),
  UNIQUE KEY uk_token_hash (token_hash),
  KEY idx_mcp_tokens_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
