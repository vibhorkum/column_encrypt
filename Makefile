MODULE_big = column_encryption
 OBJS = column_encryption.o
 
 EXTENSION = column_encryption
 DATA = column_encryption--1.0.sql
 
 SHLIB_LINK = $(shell $(PG_CONFIG) --libdir)/pgcrypto.so
 
 PG_CONFIG = pg_config
 PGXS := $(shell $(PG_CONFIG) --pgxs)
 include $(PGXS)
