--
-- We need timestamps to delete expired authorization codes
-- https://github.com/spring-projects/spring-security-oauth/issues/725
--
--
ALTER TABLE oauth_code ADD created TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
