MODULE_big = column_encrypt
 OBJS = column_encrypt.o
 
 EXTENSION = column_encrypt
DATA = column_encrypt--1.0.sql \
       column_encrypt--1.0--2.0.sql \
       column_encrypt--2.0.sql \
       column_encrypt--2.0--3.0.sql \
       column_encrypt--3.0.sql

 REGRESS = column_encrypt

 PG_CONFIG = pg_config
 PGXS := $(shell $(PG_CONFIG) --pgxs)
 include $(PGXS)
