--
-- After the upgrade to new Spring security the class signature of the serialized tokens as changed
--
-- java.io.InvalidClassException: org.springframework.security.core.authority.SimpleGrantedAuthority;
-- local class incompatible: stream classdesc serialVersionUID = 320, local class serialVersionUID = 400
--
-- Therefore we delete all existing tokens. Clients will need to re-authenticate / fetch new tokens
--
DELETE from oauth_access_token;
DELETE from oauth_refresh_token;
