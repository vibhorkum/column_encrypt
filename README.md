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

