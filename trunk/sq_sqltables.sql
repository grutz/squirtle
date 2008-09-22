CREATE DATABASE squirtle;
USE squirtle;

CREATE TABLE users (
	id SERIAL PRIMARY KEY,
	sesskey VARCHAR(32),
	timestamp VARCHAR(30),
	ip VARCHAR(16),
	browser VARCHAR(255),
	user VARCHAR(255),
	workstation VARCHAR(255),
	domain VARCHAR(255),
	nonce VARCHAR(16),
	lm VARCHAR(48),
	nt VARCHAR(48)
);

CREATE TABLE sessions (
	id serial primary key,
	sesskey_id varchar(32),
	timestamp varchar(30),
	function varchar(6),
	url varchar(255),
	nonce varchar(255),
	type2_base64 longtext,
	domain varchar(255),
	server varchar(255),
	dns_name varchar(255),
	dns_domain varchar(255),
	result varchar(255)
);

