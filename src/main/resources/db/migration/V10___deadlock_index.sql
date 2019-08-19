ALTER TABLE `oauth_access_token` ADD INDEX `oat_token_id` (`token_id`);
ALTER TABLE `oauth_access_token` ADD INDEX `oat_user_name` (`user_name`);
ALTER TABLE `oauth_access_token` ADD INDEX `oat_client_id` (`client_id`);
ALTER TABLE `oauth_access_token` ADD INDEX `oat_refresh_token` (`refresh_token`);
ALTER TABLE `oauth_refresh_token` ADD INDEX `oat_token_id` (`token_id`);
