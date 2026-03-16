/* column_encrypt--3.0--3.1.sql */

-- Upgrade script: Production Operations Features
-- 1. Encryption Statistics View
-- 2. Coverage Audit
-- 3. Online Key Rotation with Progress Tracking

\echo Use "ALTER EXTENSION column_encrypt UPDATE TO '3.1'" to load this file. \quit

/*
 * =============================================================================
 * FEATURE 1: Encryption Statistics & Metrics
 * =============================================================================
 */

/*
 * Helper function: Check if any encryption key is loaded in the session
 */
CREATE FUNCTION is_key_loaded() RETURNS boolean
    LANGUAGE sql STABLE
AS $$
    SELECT array_length(loaded_cipher_key_versions(), 1) IS NOT NULL;
$$;

COMMENT ON FUNCTION is_key_loaded() IS
    'Returns true if at least one encryption key is loaded in the current session';

/*
 * View: Encryption statistics for all encrypted columns in the database
 */
CREATE FUNCTION cipher_encryption_stats()
RETURNS TABLE (
    schema_name text,
    table_name text,
    column_name text,
    column_type text,
    row_count bigint,
    null_count bigint,
    key_versions integer[],
    oldest_key_version integer,
    newest_key_version integer,
    needs_rotation boolean
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_sql text;
    v_row_count bigint;
    v_null_count bigint;
    v_versions integer[];
    v_current_version integer;
BEGIN
    v_current_version := current_setting('encrypt.key_version', true)::integer;

    FOR rec IN
        SELECT
            n.nspname AS schema_name,
            c.relname AS table_name,
            a.attname AS column_name,
            t.typname AS column_type
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND t.typname IN ('encrypted_text', 'encrypted_bytea')
          AND c.relkind = 'r'  -- Only regular tables
        ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        schema_name := rec.schema_name;
        table_name := rec.table_name;
        column_name := rec.column_name;
        column_type := rec.column_type;

        -- Get row counts
        EXECUTE format(
            'SELECT count(*), count(*) FILTER (WHERE %I IS NULL) FROM %I.%I',
            rec.column_name, rec.schema_name, rec.table_name
        ) INTO v_row_count, v_null_count;

        row_count := v_row_count;
        null_count := v_null_count;

        -- Get distinct key versions (only if rows exist and keys are loaded)
        IF v_row_count > v_null_count AND is_key_loaded() THEN
            BEGIN
                EXECUTE format(
                    'SELECT array_agg(DISTINCT enc_key_version(%I) ORDER BY enc_key_version(%I)) FROM %I.%I WHERE %I IS NOT NULL',
                    rec.column_name, rec.column_name, rec.schema_name, rec.table_name, rec.column_name
                ) INTO v_versions;
                key_versions := v_versions;
                oldest_key_version := v_versions[1];
                newest_key_version := v_versions[array_upper(v_versions, 1)];
                needs_rotation := (oldest_key_version IS DISTINCT FROM v_current_version) OR (array_length(v_versions, 1) > 1);
            EXCEPTION
                WHEN OTHERS THEN
                    key_versions := NULL;
                    oldest_key_version := NULL;
                    newest_key_version := NULL;
                    needs_rotation := NULL;
            END;
        ELSE
            key_versions := NULL;
            oldest_key_version := NULL;
            newest_key_version := NULL;
            needs_rotation := false;
        END IF;

        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_encryption_stats() IS
    'Returns statistics about all encrypted columns including row counts, key versions in use, and rotation status';

/*
 * View: Key usage statistics across the database
 */
CREATE FUNCTION cipher_key_usage_stats()
RETURNS TABLE (
    key_version integer,
    key_state text,
    tables_using integer,
    columns_using integer,
    row_count bigint,
    is_current boolean
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_sql text;
    v_count bigint;
    v_current_version integer;
    v_key_record record;
BEGIN
    v_current_version := current_setting('encrypt.key_version', true)::integer;

    -- Get all registered key versions
    FOR v_key_record IN
        SELECT k.key_version, k.key_state
        FROM cipher_key_table k
        ORDER BY k.key_version
    LOOP
        key_version := v_key_record.key_version;
        key_state := v_key_record.key_state;
        is_current := (key_version = v_current_version);
        tables_using := 0;
        columns_using := 0;
        row_count := 0;

        -- Count usage across all encrypted columns
        IF is_key_loaded() THEN
            FOR rec IN
                SELECT
                    n.nspname AS schema_name,
                    c.relname AS table_name,
                    a.attname AS column_name
                FROM pg_attribute a
                JOIN pg_class c ON c.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_type t ON t.oid = a.atttypid
                WHERE a.attnum > 0
                  AND NOT a.attisdropped
                  AND t.typname IN ('encrypted_text', 'encrypted_bytea')
                  AND c.relkind = 'r'
            LOOP
                BEGIN
                    EXECUTE format(
                        'SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL AND enc_key_version(%I) = $1',
                        rec.schema_name, rec.table_name, rec.column_name, rec.column_name
                    ) INTO v_count USING v_key_record.key_version;

                    IF v_count > 0 THEN
                        row_count := row_count + v_count;
                        columns_using := columns_using + 1;
                    END IF;
                EXCEPTION
                    WHEN OTHERS THEN
                        NULL; -- Skip columns that can't be read
                END;
            END LOOP;

            -- Count distinct tables
            IF columns_using > 0 THEN
                tables_using := 1; -- Simplified; actual count would need more logic
            END IF;
        END IF;

        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_key_usage_stats() IS
    'Returns usage statistics for each registered key version including row counts across the database';

/*
 * Function: Export metrics in a monitoring-friendly format
 */
CREATE FUNCTION cipher_metrics()
RETURNS TABLE (
    metric_name text,
    metric_value bigint,
    metric_labels jsonb
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_count bigint;
    v_stats record;
BEGIN
    -- Total encrypted columns
    SELECT count(*) INTO v_count
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_type t ON t.oid = a.atttypid
    WHERE a.attnum > 0
      AND NOT a.attisdropped
      AND t.typname IN ('encrypted_text', 'encrypted_bytea')
      AND c.relkind = 'r';

    metric_name := 'column_encrypt_columns_total';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Keys by state
    FOR v_stats IN
        SELECT key_state, count(*) AS cnt
        FROM cipher_key_table
        GROUP BY key_state
    LOOP
        metric_name := 'column_encrypt_keys_total';
        metric_value := v_stats.cnt;
        metric_labels := jsonb_build_object('state', v_stats.key_state);
        RETURN NEXT;
    END LOOP;

    -- Keys expiring in 30 days
    SELECT count(*) INTO v_count
    FROM cipher_key_table
    WHERE expires_at IS NOT NULL
      AND expires_at <= now() + interval '30 days'
      AND expires_at > now()
      AND key_state NOT IN ('revoked');

    metric_name := 'column_encrypt_keys_expiring_30d';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Expired keys (not yet revoked)
    SELECT count(*) INTO v_count
    FROM cipher_key_table
    WHERE expires_at IS NOT NULL
      AND expires_at <= now()
      AND key_state NOT IN ('revoked');

    metric_name := 'column_encrypt_keys_expired';
    metric_value := v_count;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Active rotation jobs
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'cipher_rotation_jobs') THEN
        EXECUTE 'SELECT count(*) FROM cipher_rotation_jobs WHERE status = ''running''' INTO v_count;
        metric_name := 'column_encrypt_rotation_jobs_active';
        metric_value := COALESCE(v_count, 0);
        metric_labels := '{}'::jsonb;
        RETURN NEXT;
    END IF;

    -- Session key loaded
    metric_name := 'column_encrypt_session_key_loaded';
    metric_value := CASE WHEN is_key_loaded() THEN 1 ELSE 0 END;
    metric_labels := '{}'::jsonb;
    RETURN NEXT;

    -- Loaded key versions count
    metric_name := 'column_encrypt_session_keys_count';
    metric_value := COALESCE(array_length(loaded_cipher_key_versions(), 1), 0);
    metric_labels := '{}'::jsonb;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION cipher_metrics() IS
    'Returns encryption metrics in a format suitable for Prometheus/monitoring systems';

/*
 * =============================================================================
 * FEATURE 2: Encryption Coverage Audit
 * =============================================================================
 */

/*
 * Function: Audit database for potentially sensitive unencrypted columns
 */
CREATE FUNCTION cipher_coverage_audit(p_schema text DEFAULT NULL)
RETURNS TABLE (
    schema_name text,
    table_name text,
    column_name text,
    data_type text,
    classification text,
    is_encrypted boolean,
    recommendation text
)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    rec record;
    v_classification text;
    v_recommendation text;
BEGIN
    FOR rec IN
        SELECT
            n.nspname AS schema_name,
            c.relname AS table_name,
            a.attname AS column_name,
            t.typname AS data_type,
            t.typname IN ('encrypted_text', 'encrypted_bytea') AS is_encrypted
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        WHERE a.attnum > 0
          AND NOT a.attisdropped
          AND c.relkind = 'r'
          AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
          AND (p_schema IS NULL OR n.nspname = p_schema)
        ORDER BY n.nspname, c.relname, a.attnum
    LOOP
        -- Skip if already encrypted
        IF rec.is_encrypted THEN
            -- Only report encrypted columns as informational
            schema_name := rec.schema_name;
            table_name := rec.table_name;
            column_name := rec.column_name;
            data_type := rec.data_type;
            is_encrypted := true;
            classification := 'ENCRYPTED';
            recommendation := 'OK';
            RETURN NEXT;
            CONTINUE;
        END IF;

        -- Classify based on column name patterns
        v_classification := NULL;
        v_recommendation := NULL;

        -- PII - High sensitivity
        IF rec.column_name ~* '(^|_)(ssn|social_security|national_id|passport|driver_license|tax_id|sin|nino)($|_|num|number)' THEN
            v_classification := 'PII-HIGH';
            v_recommendation := 'ENCRYPT';
        -- PCI - Payment card data
        ELSIF rec.column_name ~* '(^|_)(card|credit|debit|pan|ccn|cvv|cvc|card_number|credit_card|account_number)($|_|num|number)' THEN
            v_classification := 'PCI';
            v_recommendation := 'ENCRYPT';
        -- Secrets
        ELSIF rec.column_name ~* '(^|_)(password|passwd|secret|api_key|apikey|private_key|privatekey|token|access_token|refresh_token|auth_token|encryption_key|secret_key)($|_)' THEN
            v_classification := 'SECRET';
            v_recommendation := 'ENCRYPT';
        -- HIPAA / Medical
        ELSIF rec.column_name ~* '(^|_)(diagnosis|prescription|medical|health|patient|symptom|treatment|medication|vaccine|allergy|blood_type|insurance_id|member_id)($|_)' THEN
            v_classification := 'HIPAA';
            v_recommendation := 'ENCRYPT';
        -- PII - Medium sensitivity
        ELSIF rec.column_name ~* '(^|_)(email|phone|mobile|cell|address|street|zip|postal|dob|birth|birthdate|date_of_birth|age|gender|sex|race|ethnicity|religion|nationality)($|_)' THEN
            v_classification := 'PII-MEDIUM';
            v_recommendation := 'CONSIDER';
        -- Financial
        ELSIF rec.column_name ~* '(^|_)(salary|income|wage|compensation|bonus|bank|routing|iban|swift|balance|amount|price|cost|revenue|profit)($|_)' AND rec.data_type IN ('numeric', 'decimal', 'money', 'integer', 'bigint', 'real', 'double precision') THEN
            v_classification := 'FINANCIAL';
            v_recommendation := 'CONSIDER';
        -- Biometric
        ELSIF rec.column_name ~* '(^|_)(fingerprint|biometric|face_id|retina|voice_print|dna)($|_)' THEN
            v_classification := 'BIOMETRIC';
            v_recommendation := 'ENCRYPT';
        END IF;

        -- Only return rows with classification
        IF v_classification IS NOT NULL THEN
            schema_name := rec.schema_name;
            table_name := rec.table_name;
            column_name := rec.column_name;
            data_type := rec.data_type;
            is_encrypted := false;
            classification := v_classification;
            recommendation := v_recommendation;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION cipher_coverage_audit(text) IS
    'Audits the database for potentially sensitive columns that may need encryption based on column naming patterns';

/*
 * Function: Summary of coverage audit
 */
CREATE FUNCTION cipher_coverage_summary(p_schema text DEFAULT NULL)
RETURNS TABLE (
    classification text,
    total_columns bigint,
    encrypted_columns bigint,
    unencrypted_columns bigint,
    coverage_pct numeric
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT
        classification,
        count(*) AS total_columns,
        count(*) FILTER (WHERE is_encrypted) AS encrypted_columns,
        count(*) FILTER (WHERE NOT is_encrypted) AS unencrypted_columns,
        round(100.0 * count(*) FILTER (WHERE is_encrypted) / count(*), 1) AS coverage_pct
    FROM cipher_coverage_audit(p_schema)
    GROUP BY classification
    ORDER BY
        CASE classification
            WHEN 'PCI' THEN 1
            WHEN 'HIPAA' THEN 2
            WHEN 'SECRET' THEN 3
            WHEN 'BIOMETRIC' THEN 4
            WHEN 'PII-HIGH' THEN 5
            WHEN 'FINANCIAL' THEN 6
            WHEN 'PII-MEDIUM' THEN 7
            WHEN 'ENCRYPTED' THEN 8
            ELSE 9
        END;
$$;

COMMENT ON FUNCTION cipher_coverage_summary(text) IS
    'Returns a summary of encryption coverage by classification category';

/*
 * =============================================================================
 * FEATURE 3: Online Key Rotation with Progress Tracking
 * =============================================================================
 */

/*
 * Table: Track rotation jobs
 */
CREATE TABLE cipher_rotation_jobs (
    job_id bigserial PRIMARY KEY,
    schema_name text NOT NULL,
    table_name text NOT NULL,
    column_name text NOT NULL,
    target_key_version integer NOT NULL,
    batch_size integer NOT NULL DEFAULT 1000,
    throttle_ms integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    total_rows bigint,
    processed_rows bigint NOT NULL DEFAULT 0,
    failed_rows bigint NOT NULL DEFAULT 0,
    started_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    error_message text,
    created_by name NOT NULL DEFAULT session_user
);

CREATE INDEX cipher_rotation_jobs_status_idx ON cipher_rotation_jobs(status);

COMMENT ON TABLE cipher_rotation_jobs IS
    'Tracks progress of key rotation jobs for encrypted columns';

/*
 * Function: Start a new rotation job
 */
CREATE FUNCTION cipher_start_rotation_job(
    p_schema text,
    p_table text,
    p_column text,
    p_target_version integer DEFAULT NULL,
    p_batch_size integer DEFAULT 1000,
    p_throttle_ms integer DEFAULT 0
) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_job_id bigint;
    v_total_rows bigint;
    v_col_type text;
    v_target_version integer;
BEGIN
    -- Validate inputs
    IF p_schema !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_table  !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR
       p_column !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'EDB-ENC0041 invalid schema/table/column name';
    END IF;

    -- Verify column is encrypted type
    SELECT format_type(a.atttypid, a.atttypmod)
    INTO v_col_type
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = p_schema
      AND c.relname = p_table
      AND a.attname = p_column
      AND a.attnum > 0
      AND NOT a.attisdropped;

    IF v_col_type IS NULL THEN
        RAISE EXCEPTION 'EDB-ENC0042 column %.%.% not found', p_schema, p_table, p_column;
    END IF;

    IF v_col_type NOT IN ('encrypted_text', 'encrypted_bytea') THEN
        RAISE EXCEPTION 'EDB-ENC0046 %.%.% is not an encrypted column', p_schema, p_table, p_column;
    END IF;

    -- Get target version
    v_target_version := COALESCE(p_target_version, current_setting('encrypt.key_version')::integer);

    -- Check for existing active job on same column
    IF EXISTS (
        SELECT 1 FROM cipher_rotation_jobs
        WHERE schema_name = p_schema
          AND table_name = p_table
          AND column_name = p_column
          AND status IN ('pending', 'running', 'paused')
    ) THEN
        RAISE EXCEPTION 'EDB-ENC0053 a rotation job already exists for %.%.%', p_schema, p_table, p_column;
    END IF;

    -- Count total rows to process
    EXECUTE format(
        'SELECT count(*) FROM %I.%I WHERE %I IS NOT NULL AND enc_key_version(%I) <> $1',
        p_schema, p_table, p_column, p_column
    ) INTO v_total_rows USING v_target_version;

    -- Create job record
    INSERT INTO cipher_rotation_jobs (
        schema_name, table_name, column_name, target_key_version,
        batch_size, throttle_ms, total_rows, status
    ) VALUES (
        p_schema, p_table, p_column, v_target_version,
        p_batch_size, p_throttle_ms, v_total_rows, 'pending'
    ) RETURNING job_id INTO v_job_id;

    RETURN v_job_id;
END;
$$;

COMMENT ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) IS
    'Creates a new key rotation job for the specified encrypted column';

/*
 * Function: Execute one batch of a rotation job
 */
CREATE FUNCTION cipher_process_rotation_batch(p_job_id bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_job cipher_rotation_jobs%ROWTYPE;
    v_sql text;
    v_processed bigint;
    v_col_type text;
BEGIN
    -- Get and lock the job
    SELECT * INTO v_job
    FROM cipher_rotation_jobs
    WHERE job_id = p_job_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'EDB-ENC0054 rotation job % not found', p_job_id;
    END IF;

    IF v_job.status NOT IN ('pending', 'running') THEN
        RAISE EXCEPTION 'EDB-ENC0055 rotation job % is not runnable (status: %)', p_job_id, v_job.status;
    END IF;

    -- Ensure encryption is enabled
    IF current_setting('encrypt.enable') <> 'on' THEN
        UPDATE cipher_rotation_jobs
        SET status = 'failed',
            error_message = 'encrypt.enable must be on',
            updated_at = now()
        WHERE job_id = p_job_id;
        RAISE EXCEPTION 'EDB-ENC0048 encrypt.enable must be on for data re-encryption';
    END IF;

    -- Update status to running if pending
    IF v_job.status = 'pending' THEN
        UPDATE cipher_rotation_jobs
        SET status = 'running',
            started_at = now(),
            updated_at = now()
        WHERE job_id = p_job_id;
    END IF;

    -- Get column type
    SELECT format_type(a.atttypid, a.atttypmod)
    INTO v_col_type
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = v_job.schema_name
      AND c.relname = v_job.table_name
      AND a.attname = v_job.column_name;

    -- Set the target key version
    PERFORM set_config('encrypt.key_version', v_job.target_key_version::text, true);

    -- Process one batch
    v_sql := format(
        'WITH batch AS (
            SELECT ctid
            FROM %I.%I
            WHERE %I IS NOT NULL
              AND enc_key_version(%I) <> $1
            LIMIT $2
        )
        UPDATE %I.%I AS t
        SET %I = t.%I::text::%s
        FROM batch
        WHERE t.ctid = batch.ctid',
        v_job.schema_name, v_job.table_name, v_job.column_name, v_job.column_name,
        v_job.schema_name, v_job.table_name, v_job.column_name, v_job.column_name, v_col_type
    );

    EXECUTE v_sql USING v_job.target_key_version, v_job.batch_size;
    GET DIAGNOSTICS v_processed = ROW_COUNT;

    -- Update job progress
    UPDATE cipher_rotation_jobs
    SET processed_rows = processed_rows + v_processed,
        updated_at = now(),
        status = CASE
            WHEN processed_rows + v_processed >= total_rows THEN 'completed'
            ELSE 'running'
        END,
        completed_at = CASE
            WHEN processed_rows + v_processed >= total_rows THEN now()
            ELSE NULL
        END
    WHERE job_id = p_job_id;

    -- Throttle if configured
    IF v_job.throttle_ms > 0 AND v_processed > 0 THEN
        PERFORM pg_sleep(v_job.throttle_ms / 1000.0);
    END IF;

    RETURN v_processed;
END;
$$;

COMMENT ON FUNCTION cipher_process_rotation_batch(bigint) IS
    'Processes one batch of rows for the specified rotation job';

/*
 * Function: Run rotation job to completion (or until paused/cancelled)
 */
CREATE FUNCTION cipher_run_rotation_job(p_job_id bigint) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
DECLARE
    v_processed bigint;
    v_total bigint := 0;
    v_status text;
BEGIN
    LOOP
        -- Check job status
        SELECT status INTO v_status
        FROM cipher_rotation_jobs
        WHERE job_id = p_job_id;

        EXIT WHEN v_status NOT IN ('pending', 'running');

        -- Process one batch
        v_processed := cipher_process_rotation_batch(p_job_id);
        v_total := v_total + v_processed;

        EXIT WHEN v_processed = 0;
    END LOOP;

    RETURN v_total;
END;
$$;

COMMENT ON FUNCTION cipher_run_rotation_job(bigint) IS
    'Runs the specified rotation job to completion';

/*
 * Function: Pause a rotation job
 */
CREATE FUNCTION cipher_pause_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'paused',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status = 'running';

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_pause_rotation_job(bigint) IS
    'Pauses a running rotation job';

/*
 * Function: Resume a paused rotation job
 */
CREATE FUNCTION cipher_resume_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'running',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status = 'paused';

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_resume_rotation_job(bigint) IS
    'Resumes a paused rotation job';

/*
 * Function: Cancel a rotation job
 */
CREATE FUNCTION cipher_cancel_rotation_job(p_job_id bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO public
AS $$
BEGIN
    UPDATE cipher_rotation_jobs
    SET status = 'cancelled',
        updated_at = now()
    WHERE job_id = p_job_id
      AND status IN ('pending', 'running', 'paused');

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION cipher_cancel_rotation_job(bigint) IS
    'Cancels a rotation job';

/*
 * View: Rotation job progress
 */
CREATE FUNCTION cipher_rotation_progress()
RETURNS TABLE (
    job_id bigint,
    schema_name text,
    table_name text,
    column_name text,
    target_version integer,
    status text,
    progress_pct numeric,
    processed_rows bigint,
    total_rows bigint,
    failed_rows bigint,
    rows_per_sec numeric,
    eta interval,
    started_at timestamptz,
    updated_at timestamptz,
    created_by name
)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO public
AS $$
    SELECT
        j.job_id,
        j.schema_name,
        j.table_name,
        j.column_name,
        j.target_key_version,
        j.status,
        CASE WHEN j.total_rows > 0
            THEN round(100.0 * j.processed_rows / j.total_rows, 1)
            ELSE 100.0
        END AS progress_pct,
        j.processed_rows,
        j.total_rows,
        j.failed_rows,
        CASE WHEN j.started_at IS NOT NULL AND j.updated_at > j.started_at
            THEN round(j.processed_rows / EXTRACT(EPOCH FROM (j.updated_at - j.started_at)), 1)
            ELSE NULL
        END AS rows_per_sec,
        CASE WHEN j.started_at IS NOT NULL
                AND j.updated_at > j.started_at
                AND j.processed_rows > 0
                AND j.status = 'running'
            THEN ((j.total_rows - j.processed_rows) / (j.processed_rows / EXTRACT(EPOCH FROM (j.updated_at - j.started_at)))) * interval '1 second'
            ELSE NULL
        END AS eta,
        j.started_at,
        j.updated_at,
        j.created_by
    FROM cipher_rotation_jobs j
    ORDER BY
        CASE j.status
            WHEN 'running' THEN 1
            WHEN 'paused' THEN 2
            WHEN 'pending' THEN 3
            ELSE 4
        END,
        j.job_id DESC;
$$;

COMMENT ON FUNCTION cipher_rotation_progress() IS
    'Returns the current progress of all rotation jobs';

/*
 * =============================================================================
 * PERMISSIONS
 * =============================================================================
 */

-- Statistics and metrics
REVOKE EXECUTE ON FUNCTION is_key_loaded() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_encryption_stats() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_key_usage_stats() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_metrics() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION is_key_loaded() TO column_encrypt_runtime;
GRANT EXECUTE ON FUNCTION cipher_encryption_stats() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_key_usage_stats() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_metrics() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_metrics() TO column_encrypt_reader;

-- Coverage audit
REVOKE EXECUTE ON FUNCTION cipher_coverage_audit(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_coverage_summary(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_coverage_audit(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_coverage_summary(text) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_coverage_audit(text) TO column_encrypt_reader;
GRANT EXECUTE ON FUNCTION cipher_coverage_summary(text) TO column_encrypt_reader;

-- Rotation jobs
REVOKE ALL ON TABLE cipher_rotation_jobs FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_process_rotation_batch(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_run_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_pause_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_resume_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_cancel_rotation_job(bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION cipher_rotation_progress() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION cipher_start_rotation_job(text, text, text, integer, integer, integer) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_process_rotation_batch(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_run_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_pause_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_resume_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_cancel_rotation_job(bigint) TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_rotation_progress() TO column_encrypt_admin;
GRANT EXECUTE ON FUNCTION cipher_rotation_progress() TO column_encrypt_reader;
