MODULE_big = column_encryption
 OBJS = column_encryption.o
 
 EXTENSION = column_encryption
 DATA = column_encryption--1.0.sql column_encryption--1.0--2.0.sql column_encryption--2.0.sql

 REGRESS = column_encryption

 PG_CONFIG = pg_config
 PGXS := $(shell $(PG_CONFIG) --pgxs)
 include $(PGXS)
