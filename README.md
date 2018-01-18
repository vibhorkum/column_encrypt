# column_encryption

## Motivation
The main motivation behind this module is that EDB Postgres should be able to provide data types which can work as Transparent Column Level encryption i.e Database users should be able to use their keys when they are inserting data in a table and data should be encrypted in a specific column. Database users who has right key should be able to access the data transparently without any modification in their SQLs.

Column encryption module comes with following two data types:
1. encrypted_text (data type for encrypted Text)
2. encrypted_bytea (data type for encrypted bytea)

## Installation steps

To install this module please use following steps:
1. Copy the source code from repository.
2. set pg_config binary location in PATH environment variable
3. Execute following command to install this module
```sql
make
make install
```

After compiling the module, follow the steps given below:
1. update shared_preload_libraries parameter of postgresql.conf of EDB Postgres
     shared_preload_libraries = '$libdir/column_encryption'
2. Restart the EDB Postgres using pg_ctl or systemctl command.
3. Use following command to install this extension in target database as given below:
```sql
psql -h server.hostname.org -p 5444 -c "CREATE EXTENSION column_encryption;" dbname
```

## How to use

1. Connect to database using psql and register your key:
```sql
SELECT cipher_key_disable_log();
SELECT cipher_key_regist('init', 'AES-DBC-AEF-GHI-JKL','aes');
SELECT cipher_key_enable_log();
```
2. After registering the key, reconnect to a session and load your key as given below:
```sql
SELECT cipher_key_disable_log();
SELECT load_key_details('AES-DBC-AEF-GHI-JKL');
SELECT cipher_key_enable_log();
```
3.  Create a table using data encrypt_bytea/encrypt_text data-types and insert some records
```sql
CREATE TABLE secure_data(id SERIAL, ssn ENCRYPTED_TEXT);
INSERT INTO secure_data(ssn) VALUES('888-999-2045');
INSERT INTO secure_data(ssn) VALUES('888-999-2046');
INSERT INTO secure_data(ssn) VALUES('888-999-2047');
```
4. Verify within the session you can access the rows:
```sql
test=# SELECT * FROM secure_data;
 id |     ssn      
----+--------------
  1 | 888-999-2045
  2 | 888-999-2046
  3 | 888-999-2047
(3 rows)
```
5. Exit from the session and connect with different session and try to Read the data:
```sql
test=# SELECT * FROM secure_data;
ERROR:  cannot decrypt data, because key was not set
```
Above result was expected since key was not set.
6. Now try to set a wrong key:
```sql
test=# SELECT cipher_key_disable_log();
 cipher_key_disable_log 
------------------------
 t
(1 row)

test=# SELECT load_key_details('AES-DBC-AEF-GHI-JKI');
ERROR:  EDB-ENC0012 cipher key is not correct
```
Above was also expected because user tried to pass the wrong key.

Module also comes with a parameter column_encrypt.encrypt_enable, which by default is on. If user disable this parameter he can query the table. However, will not be able to see the actual data. Example is given below:
```sql
test=# set column_encrypt.encrypt_enable to off;
SET
test=# select * from secure_data;
 id |                  ssn                   
----+----------------------------------------
  1 | \x0100cbac671c440c886ad3ab907d7d126f90
  2 | \x0100c9536857474fb70f9725e872ec1fc05b
  3 | \x0100002ffb04d15227b9f72431ab507c313a
(3 rows)
```

