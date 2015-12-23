# OpenConext-oauth2-server

[![Build Status](https://travis-ci.org/OpenConext/OpenConext-authorization-server.svg)](https://travis-ci.org/OpenConext/OpenConext-authorization-server)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-authorization-server/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-authorization-server)

Oauth2 server for the OpenConext platform.

# Create database

Connect to your local mysql database: `mysql -uroot`

Execute the following:

```sql
CREATE DATABASE `authzserver` DEFAULT CHARACTER SET latin1;
create user 'travis'@'localhost';
grant all on `authzserver`.* to 'travis'@'localhost';
```

# Start the app

To run locally:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`


# Adding clients
This oauth server connects to a MySQL database which contains a scheme that is predetermined by Spring Security Oauth

For clients to be able to connect, they must be known to this oAuth server. To register a client
with this server, execute the following SQL on the server's schema:

```sql
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types)
VALUES ('cool_app_id', 'groups', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e', 'read','implicit,authorization_code,refresh_token');
```

# Adding resource servers
Resource servers need to be able to check authentication tokens for validity with this server.
For resource servers to be able to do so, they need to be registered as a client. This is done by

```sql
INSERT INTO oauth_client_details (client_id, client_secret, authorities)
VALUES ('vootservice', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e','ROLE_TOKEN_CHECKER');
```

Here, 'vootservice' is the username that the resource server presents in the basic authentication header it adds to each `/oauth/check_token` request.
