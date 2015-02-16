# OpenConext-oauth2-server
Oauth2 server for the OpenConext platform.

To run locally:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`


# Adding clients
This oauth server connects to a MySQL database which contains a scheme that is predetermined by Spring Security Oauth

For clients to be able to connect, they must be known to this oAuth server. To register a client
with this server, execute the following SQL on the server's schema:

`
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope)
    VALUES ('cool_app_id', 'groups', 'secret', 'read');
`

# Adding resource servers
Resource servers need to be able to check authentication tokens for validity with this server.
For resource servers to be able to do so, they need to be registered as a client. This is done by

`
INSERT_INTO oauth_client_details (client_id, client_secret, authorities)
    values ('foobar', 'secret','ROLE_TRUSTED_CLIENT');
`

Here, 'foobar' is the username that the resource server presents in the basic authentication header it adds to each `/oauth/check_token` request.
