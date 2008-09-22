README.sql
----------

Squirtle can support everything ActiveRecord supports. It's only
been tested with the following:

    SQLite3
    MySQL
    
And has support but not tested for:

    Postgres

Configuration String
--------------------

Inside 'squirtle.yaml' the config variable 'db' is used to define the
database type and connection/file information. For example the following
string will configure Squirtle to use SQLite and use the file "squirtle.db"
as the data file:

    sqlite://squirtle.db
    
The following will configure connectivity to a MySQL server on a different
IP address with the user 'sqdb', password 'sqpass' and database 'squirtle':

    mysql://sqdb:sqpass@192.168.5.15/squirtle

Non-SQLite Databases
--------------------

Squirtle does not create the databases or tables. Table formats can be found
in the file 'sq_sqltables.sql' which can be used to create everything you need
prior to running Squirtle:

    mysql -u user -p < sq_sqltables.sql
