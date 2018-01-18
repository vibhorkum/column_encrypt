# column_encryption

## Motivation
The main motivation behind this module is that EDB Postgres should be able to provide data types which can work as Transparent Column encryption i.e Database users should be able to use their keys when they are inserting data in a table and data should be encrypted in a specific column. Database users who has right key should be able to access the data transparently without any modification in their SQL.

Column encryption module comes with following two data types:
1. encrypted_text (data type for encrypted Text)
2. encrypted_bytea (data type for encrypted bytea)

## Instalation steps

