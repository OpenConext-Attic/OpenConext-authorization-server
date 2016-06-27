--
-- Moving from MySQLto the Galera cluster requires primary keys.
--
--
ALTER TABLE oauth_code ADD id MEDIUMINT PRIMARY KEY AUTO_INCREMENT;
ALTER TABLE oauth_approvals ADD id MEDIUMINT PRIMARY KEY AUTO_INCREMENT;
ALTER TABLE oauth_refresh_token ADD id MEDIUMINT PRIMARY KEY AUTO_INCREMENT;


