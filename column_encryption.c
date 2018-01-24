#include <unistd.h>

#include "postgres.h"
#include "fmgr.h"
#include "pgstat.h"
#include "utils/guc.h"
#include "utils/palloc.h"
#include "utils/builtins.h"
#include "utils/bytea.h"
#include "commands/explain.h"
#include "tcop/tcopprot.h"
#include "mb/pg_wchar.h"
#include "access/hash.h"
#include "libpq/pqformat.h"
#include "utils/memutils.h"
#include "catalog/pg_collation.h"
#include "access/hash.h"
#include "libpq/pqformat.h"

#include "px.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif                            /* END PG_MODULE_MAGIC */

typedef struct
{
    bytea       *key;            /* encryption key */
    text       *algorithm;        /* encryption algorithm */
}            key_detail;


/* Function declarations */
Datum        pg_encrypt(PG_FUNCTION_ARGS);
Datum        pg_decrypt(PG_FUNCTION_ARGS);
void        _PG_init(void);
void        _PG_fini(void);

bytea       *pg_col_encrypt(bytea *input_data);
Datum        pg_col_decrypt(key_detail * entry, bytea *encrypted_data);
bytea       *add_header_to_encrpt_data(bytea *encrypted_data);
bytea       *rm_header_frm_encrpt_input(bytea *input_data);
bool        binary_comparison(bytea *barg1, bytea *barg2);


key_detail *create_key_detail(text *key, text *algorithm);
bool        remove_key_detail(key_detail * entry);
bool        is_key_loaded(void);

PG_FUNCTION_INFO_V1(pgstat_actv_mask);
PG_FUNCTION_INFO_V1(col_enc_text_in);
PG_FUNCTION_INFO_V1(col_enc_text_out);
PG_FUNCTION_INFO_V1(col_enc_bytea_in);
PG_FUNCTION_INFO_V1(col_enc_bytea_out);
PG_FUNCTION_INFO_V1(col_enc_comp_eq_text);
PG_FUNCTION_INFO_V1(col_enc_comp_eq_bytea);
PG_FUNCTION_INFO_V1(bool_enc_text);
PG_FUNCTION_INFO_V1(enc_text_trim);
PG_FUNCTION_INFO_V1(inet_enc_text);
PG_FUNCTION_INFO_V1(xml_enc_text);
PG_FUNCTION_INFO_V1(enc_text_regclass);
PG_FUNCTION_INFO_V1(enc_hash_encrted_data);
PG_FUNCTION_INFO_V1(enc_store_key);
PG_FUNCTION_INFO_V1(enc_store_prv_key);
PG_FUNCTION_INFO_V1(enc_rm_key);
PG_FUNCTION_INFO_V1(enc_rm_prv_key);
PG_FUNCTION_INFO_V1(col_enc_recv);
PG_FUNCTION_INFO_V1(col_enc_send);


/* enable encryption/decryption function */
static bool encrypt_enable = true;


/* whether mask mask_query_log query log or not */
static bool mask_key_log = false;

/* backup of log_min_error_statement value*/
int            backup_log_min_error_statement = -1;

/* backup of log_min_duration_statemet value */
int            backup_log_min_duration_statement = -1;

/* current encryption key */
key_detail *current_key_detail = NULL;

/* previous encryption key */
key_detail *previous_key_detail = NULL;
const short header = 1;

/* mask log messages */
static void suppress_keylog_hook(ErrorData *);

/* backup the old one */
static emit_log_hook_type prev_emit_log_hook = NULL;

/* protect from recursive call */
static bool being_hook = false;


/*
 * Module load callback
 */
void
_PG_init(void)
{
    /* load hook module */
    prev_emit_log_hook = emit_log_hook;
    emit_log_hook = suppress_keylog_hook;
    
    DefineCustomBoolVariable("encrypt.mask_key_log",
                             "mask query log messages, string within () mark will be masked by *****",
                             NULL,
                             &mask_key_log,
                             false,
                             PGC_SUSET,
                             0,
                             NULL,
                             NULL,
                             NULL);
    
    DefineCustomBoolVariable("encrypt.enable",
                             "column encryption on/off.",
                             NULL,
                             &encrypt_enable,
                             true,
                             PGC_USERSET,
                             0,
                             NULL,
                             NULL,
                             NULL);
    
}


/*
 * module unload callback
 */
void
_PG_fini(void)
{
    /* restore emit_log_hook when unload */
    if (emit_log_hook == suppress_keylog_hook)
    {
        emit_log_hook = prev_emit_log_hook;
    }
}

/* mask cipher key log hook */
/*
 * Function : suppress_keylog_hook
 * ---------------------
 * Mask query log messages.
 * String in "()" mark will be quoted by *****.
 *
 * @param    *char ARG[0]        input ErrorData*
 * @return    nothing
 */
static void
suppress_keylog_hook(ErrorData *edata)
{
    /*
     * These temporary variables below are allocated in ErrorContext.
     * PostgreSQL do not reset ErrorContext when elevel is not in ERROR,
     * FATAL, PANIC. So we must pfree in this case.
     */
    Datum        convertedMsg,
    replaceMsg_tmp,
    regex,
    regex_param,
    mask,
    flag;
    MemoryContext old_mem_context;
    
    /* call the old one if exist */
    if (prev_emit_log_hook)
    {
        prev_emit_log_hook(edata);
    }
    
    if (mask_key_log && !(being_hook))
    {
        /* Arguments of textregexreplace. */
        regex = CStringGetTextDatum("[(].+[)]"),
        mask = CStringGetTextDatum("(*****)"),
        flag = CStringGetTextDatum("g");
        
        /* protect from recursive call */
        being_hook = true;
        /* mask STATEMENT error messages */
        if (debug_query_string)
        {
            replaceMsg_tmp = CStringGetTextDatum(debug_query_string);
            convertedMsg = DirectFunctionCall4Coll(textregexreplace,
                                                   C_COLLATION_OID,
                                                   replaceMsg_tmp,
                                                   regex,
                                                   mask,
                                                   flag);
            if (replaceMsg_tmp)
            {
                px_memset((void *) replaceMsg_tmp, 0, sizeof(replaceMsg_tmp));
                pfree((void *) replaceMsg_tmp);
            }
            old_mem_context = MemoryContextSwitchTo(MessageContext);
            debug_query_string = TextDatumGetCString(convertedMsg);
            MemoryContextSwitchTo(old_mem_context);
            if (convertedMsg)
            {
                pfree((void *) convertedMsg);
            }
        }
        
        /* mask normal log messages */
        if (edata->message)
        {
            replaceMsg_tmp = CStringGetTextDatum(edata->message);
            convertedMsg = DirectFunctionCall4Coll(textregexreplace,
                                                   C_COLLATION_OID,
                                                   replaceMsg_tmp,
                                                   regex,
                                                   mask,
                                                   flag);
            if (replaceMsg_tmp)
            {
                px_memset((void *) replaceMsg_tmp, 0, sizeof(replaceMsg_tmp));
                pfree((void *) replaceMsg_tmp);
            }
            /* do not leave anything relate to key info in memory */
            px_memset(edata->message, 0, sizeof(edata->message));
            pfree(edata->message);
            edata->message = TextDatumGetCString(convertedMsg);
            if (convertedMsg)
            {
                pfree((void *) convertedMsg);
            }
        }
        
        /*
         * mask DETAIL error message edata->detail_log never include any query
         * message. so we just mask only edata->detail.
         */
        if (edata->detail)
        {
            replaceMsg_tmp = CStringGetTextDatum(edata->detail);
            convertedMsg = DirectFunctionCall4Coll(textregexreplace,
                                                   C_COLLATION_OID,
                                                   replaceMsg_tmp,
                                                   regex,
                                                   mask,
                                                   flag);
            if (replaceMsg_tmp)
            {
                px_memset((void *) replaceMsg_tmp, 0, sizeof(replaceMsg_tmp));
                pfree((void *) replaceMsg_tmp);
            }
            
            /*
             * The following must be execute only in extension protocol. But
             * can not judge whether extension protocol or not
             */
            regex_param = CStringGetTextDatum("parameters: .+");
            replaceMsg_tmp = DirectFunctionCall4Coll(textregexreplace,
                                                     C_COLLATION_OID,
                                                     convertedMsg,
                                                     regex_param,
                                                     mask,
                                                     flag);
            if (convertedMsg)
            {
                px_memset((void *) convertedMsg, 0, sizeof(convertedMsg));
                pfree((void *) convertedMsg);
            }
            if (regex_param)
            {
                pfree((void *) regex_param);
            }
            /* do not leave anything relate to key info in memory */
            px_memset(edata->detail, 0, sizeof(edata->detail));
            pfree(edata->detail);
            edata->detail = TextDatumGetCString(replaceMsg_tmp);
            if (replaceMsg_tmp)
            {
                pfree((void *) replaceMsg_tmp);
            }
        }
        
        /*
         * QUERY error message if a sql in function failed, then the query is
         * printed as QUERY message.
         */
        if (edata->internalquery)
        {
            replaceMsg_tmp = CStringGetTextDatum(edata->internalquery);
            convertedMsg = DirectFunctionCall4Coll(textregexreplace,
                                                   C_COLLATION_OID,
                                                   replaceMsg_tmp,
                                                   regex,
                                                   mask,
                                                   flag);
            if (replaceMsg_tmp)
            {
                px_memset((void *) replaceMsg_tmp, 0, sizeof(replaceMsg_tmp));
                pfree((void *) replaceMsg_tmp);
            }
            /* do not leave anything relate to key info in memory */
            px_memset(edata->internalquery, 0, sizeof(edata->internalquery));
            pfree(edata->internalquery);
            edata->internalquery = TextDatumGetCString(convertedMsg);
            if (convertedMsg)
            {
                pfree((void *) convertedMsg);
            }
        }
        
        /*
         * QUERY context message cipher key is included in edata->context
         * messages. So it must be masked
         */
        if (edata->context)
        {
            replaceMsg_tmp = CStringGetTextDatum(edata->context);
            convertedMsg = DirectFunctionCall4Coll(textregexreplace,
                                                   C_COLLATION_OID,
                                                   replaceMsg_tmp,
                                                   regex,
                                                   mask,
                                                   flag);
            if (replaceMsg_tmp)
            {
                px_memset((void *) replaceMsg_tmp, 0, sizeof(replaceMsg_tmp));
                pfree((void *) replaceMsg_tmp);
            }
            /* do not leave anything relate to key info in memory */
            px_memset(edata->context, 0, sizeof(edata->context));
            pfree(edata->context);
            edata->context = TextDatumGetCString(convertedMsg);
            if (convertedMsg)
            {
                pfree((void *) convertedMsg);
            }
        }
        if (regex)
            pfree((void *) regex);
        if (mask)
            pfree((void *) mask);
        if (flag)
            pfree((void *) flag);
        /* protect from recursive call */
        being_hook = false;
    }
}

/*
 * Function : pgstat_actv_mask
 * ---------------------
 * masked pg_stat_activity's query column to specify text.
 *
 * @param    nothing
 * @return    nothing
 */

Datum
pgstat_actv_mask(PG_FUNCTION_ARGS)
{
    elog(DEBUG2, "EDB-ENC002 masking pg_stat_activity's query.");
    pgstat_report_activity(STATE_RUNNING, "<query masking...>");
    
    PG_RETURN_VOID();
}

/*
 * Function : col_enc_text_in
 * ---------------------
 * returns ciphertext of input data(text)
 *
 * @param    *char ARG[0]        input data(plaintext)
 * @return    ciphertext of input data
 */


Datum
col_enc_text_in(PG_FUNCTION_ARGS)
{
    char       *input_text = PG_GETARG_CSTRING(0);    /* input plain text
                                                       * parameter */
    bytea       *encrypted_data = NULL;    /* encryption data */
    bytea       *result = NULL;    /* header + encyrpted_data  */
    bytea       *plain_data = NULL;
    
    /* if encrypt_enable is true, encrypting plain text and return */
    if (encrypt_enable)
    {
        plain_data = (bytea *) DatumGetPointer(DirectFunctionCall1(textin, CStringGetDatum(input_text)));
        encrypted_data = pg_col_encrypt(plain_data);
        pfree(plain_data);
        
        /* add header(dummy) to encrypted data */
        result = add_header_to_encrpt_data(encrypted_data);
        pfree(encrypted_data);
        
        PG_RETURN_BYTEA_P(result);
    }
    /* if encrypt_enable is not true return plain text */
    else
    {
        PG_RETURN_DATUM(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
    }
}


/*
 * Function : col_enc_text_out
 * ---------------------
 * returns plaintext of input data
 *
 * @param    *char ARG[0]    input data(ciphertext)
 * @return    plaintext of input data(text)
 */

Datum
col_enc_text_out(PG_FUNCTION_ARGS)
{
    bytea       *input_data = PG_GETARG_BYTEA_PP(0); /* pointer of input
                                                      * ciphertext  */
    bytea       *encrypted_data = NULL;    /* remove header of ciphertext */
    key_detail *entry = NULL;    /* key */
    Datum        result;
    Datum        tmp_result;
    
    /* if encrypt_enable is true, decrypt input data and return */
    if (encrypt_enable)
    {
        /* if old key is exists, re-encryption is working now */
        if (previous_key_detail != NULL)
        {
            entry = previous_key_detail;
        }
        else
        {
            entry = current_key_detail;
        }
        
        /* remove header from input data */
        encrypted_data = rm_header_frm_encrpt_input(input_data);
        /* decrypting ciphertext */
        tmp_result = pg_col_decrypt(entry, encrypted_data);
        result = DirectFunctionCall1(textout, tmp_result);
        
        pfree(encrypted_data);
        pfree(DatumGetPointer(tmp_result));
    }
    /* if encrypt_enable is false return ciphertext */
    else
    {
        result = DirectFunctionCall1(byteaout, PointerGetDatum(input_data));
    }
    
    PG_FREE_IF_COPY(input_data, 0);
    
    PG_RETURN_DATUM(result);
}


/*
 * Function : col_enc_bytea_in
 * ---------------------
 * returns ciphertext of input data(binary)
 *
 * @param    *char ARG[0]    input data(plaintext)
 * @return    ciphertext of input data
 */


Datum
col_enc_bytea_in(PG_FUNCTION_ARGS)
{
    char       *input_text = PG_GETARG_CSTRING(0);    /* input plain text
                                                       * parameter */
    bytea       *encrypted_data = NULL;    /* encryption data */
    bytea       *result = NULL;    /* header + encrypted_data */
    bytea       *plain_data = NULL;
    
    /* if encrypt_enable is true, encrypting plain text and return */
    if (encrypt_enable)
    {
        /* get key and encryption algorithm and encrypt data */
        plain_data = (bytea *) DatumGetPointer(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
        encrypted_data = pg_col_encrypt(plain_data);
        pfree(plain_data);
        /* add header information to encrypted data */
        result = add_header_to_encrpt_data(encrypted_data);
        pfree(encrypted_data);
        PG_RETURN_BYTEA_P(result);
    }
    /* if encrypt_enable is not true return plain text */
    else
    {
        PG_RETURN_DATUM(DirectFunctionCall1(byteain, CStringGetDatum(input_text)));
    }
}


/*
 * Function : col_enc_bytea_out
 * ---------------------
 * returns plaintext of input data
 *
 * @param    *char ARG[0]        input data(ciphertext)
 * @return    plaintext of input data(binary)
 */


Datum
col_enc_bytea_out(PG_FUNCTION_ARGS)
{
    bytea       *input_data = PG_GETARG_BYTEA_PP(0); /* pointer of input
                                                      * ciphertext  */
    
    bytea       *encrypted_data = NULL;    /* remove header of ciphertext */
    key_detail *entry = NULL;    /* key */
    Datum        result;
    Datum        tmp_result;
    
    /* if encrypt_enable is true, decrypt input data and return */
    if (encrypt_enable)
    {
        /* if key is not set print error and exit */
        if (previous_key_detail != NULL)
        {
            entry = previous_key_detail;
        }
        else
        {
            entry = current_key_detail;
        }
        
        /* remove header information from input data */
        encrypted_data = rm_header_frm_encrpt_input(input_data);
        
        /* decrypting ciphertext */
        tmp_result = pg_col_decrypt(entry, encrypted_data);
        result = DirectFunctionCall1(byteaout, tmp_result);
        
        pfree(encrypted_data);
        pfree(DatumGetPointer(tmp_result));
    }
    /* if encrypt_enable is false return ciphertext */
    else
    {
        result = DirectFunctionCall1(byteaout, PointerGetDatum(input_data));
    }
    
    PG_FREE_IF_COPY(input_data, 0);
    PG_RETURN_DATUM(result);
}

/*
 * Function : col_enc_comp_eq_text
 * ---------------------
 * return true if two input ciphertext are equal
 *
 * @param    *bytea ARG[0]    input data1(cipher text)
 * @param    *bytea ARG[1]    input data2(cipher text)
 * @return    true ARG[0] and ARG[1] are equal
 */

Datum
col_enc_comp_eq_text(PG_FUNCTION_ARGS)
{
    bytea       *barg1 = PG_GETARG_BYTEA_PP(0);
    bytea       *barg2 = PG_GETARG_BYTEA_PP(1);
    bool        result = binary_comparison(barg1, barg2);
    
    PG_FREE_IF_COPY(barg1, 0);
    PG_FREE_IF_COPY(barg2, 1);
    
    PG_RETURN_BOOL(result);
}

/*
 * Function : col_enc_comp_eq_bytea
 * ---------------------
 * return true if two binary input ciphertext are equal
 *
 * @param    *bytea ARG[0]    input data1(cipher text)
 * @param    *bytea ARG[1]    input data2(cipher text)
 * @return    true if it is true ARG[0] and ARG[1] are equal
 */


Datum
col_enc_comp_eq_bytea(PG_FUNCTION_ARGS)
{
    bytea       *barg1 = PG_GETARG_BYTEA_PP(0);
    bytea       *barg2 = PG_GETARG_BYTEA_PP(1);
    bool        result = binary_comparison(barg1, barg2);
    
    PG_FREE_IF_COPY(barg1, 0);
    PG_FREE_IF_COPY(barg2, 1);
    
    PG_RETURN_BOOL(result);
}

/*
 * bool_enc_text  - cast function for bool => encrypted text
 *
 * We need this because it's different from the behavior of boolout();
 * this function follows the SQL-spec result (except for producing lower case)
 */

Datum
bool_enc_text(PG_FUNCTION_ARGS)
{
    bool        arg1 = PG_GETARG_BOOL(0);
    const char *str;
    
    if (arg1)
    {
        str = "true";
    }
    else
    {
        str = "false";
    }
    
    PG_RETURN_DATUM(DirectFunctionCall1(col_enc_text_in, CStringGetDatum(str)));
}


/*
 * enc_text_trim   - cast function for encrypted text for rtrim
 *
 * We need this because it's different from the behavior of boolout();
 * this function follows the SQL-spec result (except for producing lower case)
 */

Datum
enc_text_trim(PG_FUNCTION_ARGS)
{
    text       *str = (text *) DatumGetPointer(DirectFunctionCall1(rtrim1, PG_GETARG_DATUM(0)));
    
    PG_RETURN_DATUM(DirectFunctionCall1(col_enc_text_in, CStringGetDatum(text_to_cstring(str))));
}

/*
 *              inet_text_trim   - cast function for inet => encrypted_text
 */

Datum
inet_enc_text(PG_FUNCTION_ARGS)
{
    text       *str = (text *) DatumGetPointer(DirectFunctionCall1(network_show, PG_GETARG_DATUM(0)));
    
    PG_RETURN_DATUM(DirectFunctionCall1(col_enc_text_in, CStringGetDatum(text_to_cstring(str))));
}

/*
 *  xml_text_trim   - cast function for xml => encrypted_text
 */


Datum
xml_enc_text(PG_FUNCTION_ARGS)
{
    text       *str = (text *) PG_GETARG_TEXT_PP(0);
    
    PG_RETURN_DATUM(DirectFunctionCall1(col_enc_text_in, CStringGetDatum(text_to_cstring(str))));
}

/*
 * enc_text_regclass: convert text to regclass
 *
 */

Datum
enc_text_regclass(PG_FUNCTION_ARGS)
{
    char       *str = NULL;
    
    str = (char *) DatumGetCString(DirectFunctionCall1(col_enc_text_out, PG_GETARG_DATUM(0)));
    
    PG_RETURN_DATUM(DirectFunctionCall1(text_regclass, PointerGetDatum(cstring_to_text((str)))));
}

/*
 * Function : enc_hash_encrted_data
 * ---------------------------------
 * return hash value of input cipher text(text/binary)
 *
 * @param    varlena ARG[0]    value for create hash
 * @return    hash value of input data
 */


Datum
enc_hash_encrted_data(PG_FUNCTION_ARGS)
{
    struct varlena *key = PG_GETARG_VARLENA_PP(0);
    
    Datum        result;
    
    result = hash_any((unsigned char *) VARDATA_ANY(key),
                      VARSIZE_ANY_EXHDR(key));
    
    /* avoiding leaking memory for toasted input */
    PG_FREE_IF_COPY(key, 0);
    
    return result;
}


/*
 * Function : create_key_detail
 * -----------------------------
 * returns key details
 *
 * @param    varlena ARG[0]    value for create hash
 * @return    hash value of input data
 */

key_detail *
create_key_detail(text *key, text *algorithm)
{
    key_detail *entry;
    MemoryContext old_mem_context;
    
    /* cipher key must be stored in TopMemoryContext */
    old_mem_context = MemoryContextSwitchTo(TopMemoryContext);
    entry = (key_detail *) palloc(sizeof(key_detail));
    
    entry->key = (bytea *) palloc(VARSIZE(key));
    memcpy((char *) entry->key, (char *) key, VARSIZE(key));
    
    entry->algorithm = (text *) palloc(VARSIZE(algorithm));
    memcpy((char *) entry->algorithm, (char *) algorithm, VARSIZE(algorithm));
    
    MemoryContextSwitchTo(old_mem_context);
    
    return entry;
}

/*
 * Function: remove_key_details
 * -----------------------------
 * Returns: boolean
 * @argument: Key_detail
 *
 * Remove key detail from session memory
 */
bool
remove_key_detail(key_detail * entry)
{
    if (entry != NULL)
    {
        if (entry->key != NULL)
        {
            /* remove all info realted to in memory */
            px_memset(entry->key, 0, sizeof(entry->key));
            pfree(entry->key);
        }
        if (entry->algorithm != NULL)
        {
            pfree(entry->algorithm);
        }
        pfree(entry);
        return true;
    }
    return false;
}

/*
 * Function : enc_store_key
 * -------------------------------
 * register current_key_detail
 *
 * @param    *text ARG[0]    encryption key
 * @param    *text ARG[1]    encryption algorithm
 */

Datum
enc_store_key(PG_FUNCTION_ARGS)
{
    text       *key = PG_GETARG_TEXT_P(0);    /* encryption key */
    text       *algorithm = PG_GETARG_TEXT_P(1);    /* encryption algorithm */
    
    remove_key_detail(current_key_detail);
    /* set current key information */
    current_key_detail = create_key_detail(key, algorithm);
    
    PG_RETURN_BOOL(true);
}

/*
 * Function : enc_store_prv_key
 * -----------------------------------------
 * regist previous_key_detail
 *
 * @param    *text ARG[0]    old encryption key
 * @param    *text ARG[1]    old encryption algorithm
 * @return    address of old key information in variable
 *
 */


Datum
enc_store_prv_key(PG_FUNCTION_ARGS)
{
    text       *key = PG_GETARG_TEXT_P(0);    /* encryption key */
    text       *algorithm = PG_GETARG_TEXT_P(1);    /* encryption algorithm */
    
    remove_key_detail(previous_key_detail);
    /* set previous key information */
    previous_key_detail = create_key_detail(key, algorithm);
    
    PG_RETURN_BOOL(true);
}


/* Function : enc_rm_key
 * --------------------------------
 * drop cipher key information from memory
 */

Datum
enc_rm_key(PG_FUNCTION_ARGS)
{
    if (remove_key_detail(current_key_detail))
    {
        current_key_detail = NULL;
        PG_RETURN_BOOL(true);
    }
    PG_RETURN_BOOL(false);
}


/*
 * Function : enc_rm_prv_key
 * ---------------------
 * clear of old key information
 * @return false if old key is already set
 */

Datum
enc_rm_prv_key(PG_FUNCTION_ARGS)
{
    if (remove_key_detail(previous_key_detail))
    {
        previous_key_detail = NULL;
        PG_RETURN_BOOL(true);
    }
    PG_RETURN_BOOL(false);
}


/*
 * Function: is_key_loaded
 * return true, if encryption key is set
 */
bool
is_key_loaded()
{
    /* if key is not set return false */
    if (current_key_detail == NULL)
    {
        return false;
    }
    return true;
}


/* encrypt input_data using lastest key and return */
bytea *
pg_col_encrypt(bytea *input_data)
{
    bytea       *encrypted_data;
    
    if (!is_key_loaded())
    {
        ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
                        errmsg("cannot encrypt data, because key was not set")));
    }
    encrypted_data = (bytea *) DatumGetPointer(DirectFunctionCall3(pg_encrypt,
                                                                   PointerGetDatum(input_data), PointerGetDatum(current_key_detail->key),
                                                                   PointerGetDatum(current_key_detail->algorithm)));
    return encrypted_data;
}

/* decrypt encrypted_data using entry and return */
Datum
pg_col_decrypt(key_detail * entry, bytea *encrypted_data)
{
    Datum        result;
    
    if (!is_key_loaded())
    {
        ereport(ERROR, (errcode(ERRCODE_IO_ERROR),
                        errmsg("cannot decrypt data, because key was not set")));
    }
    result = DirectFunctionCall3(pg_decrypt, PointerGetDatum(encrypted_data),
                                 PointerGetDatum(entry->key), PointerGetDatum(entry->algorithm));
    return result;
}

/* add header to encrypted data */
bytea *
add_header_to_encrpt_data(bytea *encrypted_data)
{
    bytea       *result = NULL;
    
    result = (bytea *) palloc(VARSIZE(encrypted_data) + sizeof(short));
    
    /* add key header information to encrypted data */
    SET_VARSIZE(result, VARSIZE(encrypted_data) + sizeof(short));
    memcpy(VARDATA(result), &header, sizeof(short));
    memcpy((VARDATA(result) + sizeof(short)), VARDATA_ANY(encrypted_data),
           VARSIZE_ANY_EXHDR(encrypted_data));
    return result;
}

/* remove header from input data */
bytea *
rm_header_frm_encrpt_input(bytea *input_data)
{
    bytea       *encrypted_data = NULL;
    
    /* remove version from input data */
    encrypted_data = (bytea *) palloc(
                                      VARSIZE_ANY_EXHDR(input_data) - sizeof(short) + VARHDRSZ);
    SET_VARSIZE(encrypted_data,
                VARSIZE_ANY_EXHDR(input_data) - sizeof(short) + VARHDRSZ);
    memcpy(VARDATA(encrypted_data), (VARDATA_ANY(input_data) + sizeof(short)),
           VARSIZE_ANY_EXHDR(input_data) - sizeof(short));
    return encrypted_data;
}


/*
 * Following contents are from PostgreSQL 10.0 backend.
 * copied from PostgreSQL 10.0(backend/utils/adt/varlena.c)
 *        bytearecv            - converts external binary format to bytea
 */
Datum
col_enc_recv(PG_FUNCTION_ARGS)
{
    StringInfo    buf = (StringInfo) PG_GETARG_POINTER(0);
    bytea       *result;
    int            nbytes;
    int32        typmod = -1;
#ifdef NOT_USED
    Oid            typelem = InvalidOid;
#endif
    
    if (PG_NARGS() > 1)
    {
#ifdef NOT_USED
        typelem = PG_GETARG_OID(1);
#endif
        typmod = PG_GETARG_INT32(2);
    }
    
    nbytes = buf->len - buf->cursor;
    
    /* If typmod is -1 (or invalid), or string is greator then typmod */
    if (typmod != -1 && typmod < nbytes)
        ereport(ERROR,
                (errcode(ERRCODE_STRING_DATA_RIGHT_TRUNCATION),
                 errmsg("value too long for type raw(%d)",
                        (int) typmod)));
    
    result = (bytea *) palloc(nbytes + VARHDRSZ);
    SET_VARSIZE(result, nbytes + VARHDRSZ);
    pq_copymsgbytes(buf, VARDATA(result), nbytes);
    PG_RETURN_BYTEA_P(result);
}

/*
 * col_enc_send                       - converts bytea to binary format
 *
 * This is a special case: just copy the input...
 */
Datum
col_enc_send(PG_FUNCTION_ARGS)
{
    bytea       *vlena = PG_GETARG_BYTEA_P_COPY(0);
    
    PG_RETURN_BYTEA_P(vlena);
}



/* return true , if binary arg1 and arg2 are equal */
bool
binary_comparison(bytea *barg1, bytea *barg2)
{
    int            len1 = VARSIZE_ANY_EXHDR(barg1);
    int            len2 = VARSIZE_ANY_EXHDR(barg2);
    bool        result;
    
    /* return false, if length of barg1 and barg2 are different */
    if (len1 != len2)
    {
        result = false;
    }
    else
    {
        result = (memcmp(VARDATA_ANY(barg1), VARDATA_ANY(barg2), len1) == 0);
    }
    return result;
}
<<<<<<< HEAD


=======
>>>>>>> 928837795ade3c94eb27eb854d9e3f44ac0bb079
