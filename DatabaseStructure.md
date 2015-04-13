# Squirtle Database Structure #

Using ActiveRecord Squirtle's main database contains the session information for clients who have connected and all user hashes that have been received.

### Sessions ###

Any client that connects to Squirtle will have a session stored in here.

```
       CREATE TABLE sessions (
               id integer primary key,
               key_id varchar(32),
               timestamp varchar(30),
               function varchar(6),
               url varchar(255),
               nonce varchar(255),
               type2_base64 varchar(255),
               domain varchar(255),
               server varchar(255),
               dns_name varchar(255),
               dns_domain varchar(255),
               result varchar(255)
        )
```

### Users ###

All hashes received are stored here.

```
	CREATE TABLE users (
		id integer primary key,
		key varchar(32),
		timestamp varchar(30),
		ip varchar(16),
		browser varchar(255),
		user varchar(255),
		workstation varchar(255),
		domain varchar(255),
		nonce varchar(16),
		lm varchar(48),
		nt varchar(48)
	)
```