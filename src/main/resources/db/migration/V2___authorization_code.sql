create table oauth_code (
  code VARCHAR(256),
  authentication BLOB
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_cs;
