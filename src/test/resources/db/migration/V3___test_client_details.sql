DELETE FROM `oauth_client_details` where `client_id` = 'test_client';
INSERT INTO `oauth_client_details` (`client_id`, `resource_ids`, `client_secret`, `scope`, `authorized_grant_types`, `web_server_redirect_uri`, `authorities`, `access_token_validity`, `refresh_token_validity`, `additional_information`, `autoapprove`)
VALUES
	('test_client', NULL, '$2a$10$zIvukHqZA7nfaZTNNP2i/e8tX/TdlwMkQSq9uq7FHZrcRJgPIUFUC', 'read,write', 'client_credentials,authorization_code', NULL, NULL, NULL, NULL, NULL, 'true');
