--
-- We want to prevent open redirect with resource servers
--
--
UPDATE oauth_client_details SET authorized_grant_types = 'resource_server'
    WHERE authorities = 'ROLE_TOKEN_CHECKER' AND (authorized_grant_types IS NULL OR authorized_grant_types = '');

