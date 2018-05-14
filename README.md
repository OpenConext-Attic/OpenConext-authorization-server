# OpenConext-oauth2-server

[![Build Status](https://travis-ci.org/OpenConext/OpenConext-authorization-server.svg)](https://travis-ci.org/OpenConext/OpenConext-authorization-server)
[![codecov.io](https://codecov.io/github/OpenConext/OpenConext-authorization-server/coverage.svg)](https://codecov.io/github/OpenConext/OpenConext-authorization-server)

OAuth2 Spring based Authorization server for the OpenConext platform.

## Create database

Connect to your local mysql database: `mysql -uroot`

Execute the following:

```sql
CREATE DATABASE `authzserver` DEFAULT CHARACTER SET latin1;
grant all on `authzserver`.* to 'root'@'localhost';
```

## Start the app

To run locally:

`mvn spring-boot:run -Drun.jvmArguments="-Dspring.profiles.active=dev"`


## Adding clients

This oauth server connects to a MySQL database which contains a scheme that is predetermined by Spring Security Oauth

For clients to be able to connect, they must be known to this oAuth server. To register a (super) client
with this server, execute the following SQL on the server's schema:

```sql
INSERT INTO oauth_client_details (client_id, resource_ids, client_secret, scope, authorized_grant_types, authorities, web_server_redirect_uri, autoapprove)
VALUES ('cool_app_id', 'groups', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e', 'read',
'client_credentials,implicit,authorization_code,refresh_token', 'ROLE_TOKEN_CHECKER', 'http://localhost:8081', 'true');
```
Note that the user `cool_app_id` has all known grant_types as well as the right to introspect tokens. This is not realistic for production clients.

## Adding resource servers

Resource servers need to be able to check authentication tokens for validity with this server.
For resource servers to be able to do so, they need to be registered as a client. This is done by

```sql
INSERT INTO oauth_client_details (client_id, client_secret, authorities)
VALUES ('vootservice', '$2a$10$HjC4gZZYgVIO.Hxn0h9w1em/rJ2StyvcHbU8cpcMUK5D8OIL.Zv.e','ROLE_TOKEN_CHECKER');
```

Here, 'vootservice' is the username that the resource server presents in the basic authentication header it adds to each `/oauth/check_token` request.

## Retrieving tokens

Start the application with the dev profile and request for an authorization code:
```
curl -v  'http://localhost:8080/oauth/authorize?response_type=code&client_id=cool_app_id&scope=read&redirect_uri=http://localhost:8081'
```
This works because of the dev profile that mocks shibboleth and add authentication headers to incoming requests. The response contains the 
oauth code in the location response header:
```
Location: http://localhost:8081?code=KFhrLw
export code=KFhrLw
```
Use the code to obtain a token:
```
curl -u cool_app_id:secret -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d "code=$code&grant_type=authorization_code&redirect_uri=http://localhost:8081" 'http://localhost:8080/oauth/token'
``` 
And the result contains the access_token and refresh_token:
```
{
  "access_token": "71366be6-790b-4d05-90fd-94d95e221a7c",
  "token_type": "bearer",
  "refresh_token": "f463adcd-48cd-4d60-a19c-1a0d2b382598",
  "expires_in": 15551933,
  "scope": "read"
}
```
And introspect the token:
```
export token=71366be6-790b-4d05-90fd-94d95e221a7c
curl -u cool_app_id:secret "http://localhost:8080/oauth/check_token?token=$token" | jq
{
  "aud": [
    "groups"
  ],
  "authenticatingAuthority": "engineblock.org",
  "user_name": "urn:collab:person:example.com:admin",
  "displayName": "John Doe",
  "scope": [
    "read"
  ],
  "schacHomeOrganization": "surfnet.nl",
  "active": true,
  "eduPersonPrincipalName": "j.doe@example.com",
  "exp": 1541845636,
  "authorities": [
    "ROLE_USER"
  ],
  "email": "j.doe@example.com",
  "client_id": "cool_app_id"
}
```

## LifeCycle Deprovisioning

Authz-Server has a LifeCycle API to deprovision users. The preview endpoint:
```
curl -u user:secret http://localhost:8080/deprovision/urn:collab:person:example.com:admin | jq 
```
And the actual `Deprovisioning` of the user:
```
curl -X DELETE -u user:secret http://localhost:8080/deprovision/urn:collab:person:example.com:admin | jq
```
