BEGIN;

CREATE SCHEMA IF NOT EXISTS logs_api;
CREATE SCHEMA IF NOT EXISTS logs_maint;

DO $guard$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class
    WHERE relname = 'logs'
      AND relnamespace = 'public'::regnamespace
      AND relkind = 'r'
  ) THEN
    RAISE NOTICE 'dropping unpartitioned public.logs left by fluent-bit auto-create';
    DROP TABLE public.logs;
  END IF;
END
$guard$;

CREATE TABLE IF NOT EXISTS public.logs (
  tag       varchar,
  "time"    timestamp,
  data      jsonb,
  namespace text GENERATED ALWAYS AS (data #>> '{kubernetes,namespace_name}') STORED,
  pod       text GENERATED ALWAYS AS (data #>> '{kubernetes,pod_name}') STORED,
  container text GENERATED ALWAYS AS (data #>> '{kubernetes,container_name}') STORED,
  stream    text GENERATED ALWAYS AS (data ->> 'stream') STORED,
  message   text GENERATED ALWAYS AS (data ->> 'log') STORED,
  labels    jsonb GENERATED ALWAYS AS (data #> '{kubernetes,labels}') STORED,
  unit      text GENERATED ALWAYS AS (data ->> 'SYSTEMD_UNIT') STORED,
  node      text GENERATED ALWAYS AS (data ->> 'HOSTNAME') STORED
) PARTITION BY RANGE ("time");

ALTER TABLE public.logs
  ADD COLUMN IF NOT EXISTS labels jsonb
  GENERATED ALWAYS AS (data #> '{kubernetes,labels}') STORED;

ALTER TABLE public.logs
  ADD COLUMN IF NOT EXISTS unit text
  GENERATED ALWAYS AS (data ->> 'SYSTEMD_UNIT') STORED,
  ADD COLUMN IF NOT EXISTS node text
  GENERATED ALWAYS AS (data ->> 'HOSTNAME') STORED;

CREATE TABLE IF NOT EXISTS public.logs_default PARTITION OF public.logs DEFAULT;

CREATE INDEX IF NOT EXISTS logs_time_idx ON public.logs ("time" DESC);
CREATE INDEX IF NOT EXISTS logs_ns_time_idx ON public.logs (namespace, "time" DESC);
CREATE INDEX IF NOT EXISTS logs_pod_time_idx ON public.logs (pod, "time" DESC);
CREATE INDEX IF NOT EXISTS logs_unit_time_idx ON public.logs (unit, "time" DESC);
CREATE INDEX IF NOT EXISTS logs_node_time_idx ON public.logs (node, "time" DESC);

CREATE INDEX IF NOT EXISTS logs_labels_idx ON public.logs USING gin (labels);

DROP FUNCTION IF EXISTS logs_maint.rotate(int, int);

CREATE OR REPLACE FUNCTION logs_maint.rotate(
  ahead_days  int     DEFAULT 7,
  retain_days int     DEFAULT 14,
  pvc_bytes   bigint  DEFAULT NULL,
  size_frac   numeric DEFAULT 0.75
) RETURNS TABLE (action text, partition_name text, bytes bigint)
LANGUAGE plpgsql AS $rotate$
DECLARE
  d       date;
  nm      text;
  cutoff  date;
  freed   bigint;
  db_size bigint;
  budget  bigint;
BEGIN
  FOR d IN
    SELECT generate_series(current_date, current_date + ahead_days, '1 day')::date
  LOOP
    nm := 'logs_p' || to_char(d, 'YYYYMMDD');
    IF NOT EXISTS (
      SELECT 1 FROM pg_class
      WHERE relname = nm AND relnamespace = 'public'::regnamespace
    ) THEN
      EXECUTE format(
        'CREATE TABLE public.%I PARTITION OF public.logs FOR VALUES FROM (%L) TO (%L)',
        nm, d, d + 1);
      action := 'created';
      partition_name := nm;
      bytes := NULL;
      RETURN NEXT;
    END IF;
  END LOOP;

  cutoff := current_date - retain_days;
  FOR nm IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_inherits i ON i.inhrelid = c.oid
    WHERE i.inhparent = 'public.logs'::regclass
      AND c.relname ~ '^logs_p[0-9]{8}$'
      AND to_date(right(c.relname, 8), 'YYYYMMDD') < cutoff
    ORDER BY c.relname
  LOOP
    freed := pg_total_relation_size(format('public.%I', nm)::regclass);
    EXECUTE format('DROP TABLE public.%I', nm);
    RAISE NOTICE 'logs_maint.rotate: dropped % (age retention, % bytes freed)', nm, freed;
    action := 'dropped';
    partition_name := nm;
    bytes := freed;
    RETURN NEXT;
  END LOOP;

  IF pvc_bytes IS NOT NULL THEN
    budget := (pvc_bytes * size_frac)::bigint;
    db_size := pg_database_size(current_database());

    WHILE db_size > budget LOOP
      SELECT c.relname INTO nm
      FROM pg_class c
      JOIN pg_inherits i ON i.inhrelid = c.oid
      WHERE i.inhparent = 'public.logs'::regclass
        AND c.relname ~ '^logs_p[0-9]{8}$'
        AND to_date(right(c.relname, 8), 'YYYYMMDD') < current_date
      ORDER BY c.relname
      LIMIT 1;

      EXIT WHEN nm IS NULL;

      freed := pg_total_relation_size(format('public.%I', nm)::regclass);
      EXECUTE format('DROP TABLE public.%I', nm);
      RAISE WARNING 'logs_maint.rotate: % bytes > % byte budget (% bytes PVC x %) -- dropped % early (% bytes freed)',
        db_size, budget, pvc_bytes, size_frac, nm, freed;
      action := 'dropped_size_cap';
      partition_name := nm;
      bytes := freed;
      RETURN NEXT;

      db_size := pg_database_size(current_database());
    END LOOP;

    IF db_size > budget THEN
      RAISE WARNING 'logs_maint.rotate: still % bytes > % byte budget after dropping every eligible partition -- only logs_default and/or today''s partition remain',
        db_size, budget;
    END IF;
  END IF;
END;
$rotate$;

SELECT logs_maint.rotate();


CREATE OR REPLACE FUNCTION logs_maint.label_match(labels jsonb, selector text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $label_match$
DECLARE
  term text;
  key  text;
  val  text;
  vals text[];
BEGIN
  IF selector IS NULL OR btrim(selector) = '' THEN
    RETURN true;
  END IF;
  IF labels IS NULL THEN
    labels := '{}'::jsonb;
  END IF;

  FOREACH term IN ARRAY regexp_split_to_array(selector, ',(?![^()]*\))') LOOP
    term := btrim(term);
    CONTINUE WHEN term = '';

    IF term LIKE '!%' THEN
      IF labels ? btrim(substring(term FROM 2)) THEN RETURN false; END IF;

    ELSIF term ~* '\Wnotin\s*\(' THEN
      key := btrim(regexp_replace(term, '(?i)\s*notin\s*\(.*$', ''));
      SELECT array_agg(btrim(s.v)) INTO vals
      FROM unnest(string_to_array(substring(term FROM '\((.*)\)'), ',')) AS s(v);
      IF COALESCE(labels ->> key = ANY(vals), false) THEN RETURN false; END IF;

    ELSIF term ~* '\Win\s*\(' THEN
      key := btrim(regexp_replace(term, '(?i)\s*in\s*\(.*$', ''));
      SELECT array_agg(btrim(s.v)) INTO vals
      FROM unnest(string_to_array(substring(term FROM '\((.*)\)'), ',')) AS s(v);
      IF NOT COALESCE(labels ->> key = ANY(vals), false) THEN RETURN false; END IF;

    ELSIF term LIKE '%!=%' THEN
      key := btrim(split_part(term, '!=', 1));
      val := btrim(split_part(term, '!=', 2));
      IF labels ->> key IS NOT DISTINCT FROM val THEN RETURN false; END IF;

    ELSIF term LIKE '%==%' THEN
      key := btrim(split_part(term, '==', 1));
      val := btrim(split_part(term, '==', 2));
      IF labels ->> key IS DISTINCT FROM val THEN RETURN false; END IF;

    ELSIF term LIKE '%=%' THEN
      key := btrim(split_part(term, '=', 1));
      val := btrim(split_part(term, '=', 2));
      IF labels ->> key IS DISTINCT FROM val THEN RETURN false; END IF;

    ELSE
      IF NOT (labels ? term) THEN RETURN false; END IF;
    END IF;
  END LOOP;

  RETURN true;
END
$label_match$;

COMMENT ON FUNCTION logs_maint.label_match(jsonb, text) IS
  'Internal predicate: evaluates a kubectl label selector against one label set.';

CREATE OR REPLACE VIEW logs_api.entries AS
SELECT
  l."time"    AS at,
  l.namespace AS namespace,
  l.pod       AS pod,
  l.container AS container,
  l.stream    AS stream,
  l.message   AS message,
  l.labels    AS labels
FROM public.logs l
WHERE l.tag NOT LIKE 'host.%';

COMMENT ON VIEW logs_api.entries IS
  'Every captured container log line, newest first when ordered by "at". This is the raw feed: prefer the purpose-built endpoints (recent, errors, search, pod_tail) unless you need an arbitrary filter combination. Retention is 14 days; anything older has been dropped. This store retains error-signal lines only, not all container output. An empty result means no matching error-signal lines were recorded -- it does not mean the workload was silent, and it does not mean the pipeline is broken. To tell those apart, call workloads or volume: if they return rows, ingest is healthy. For a workload''s normal, unfiltered output use the flux MCP''s `get_kubernetes_logs` tool, which reads the live kubelet tail. The log pipeline''s own components -- fluent-bit, logs-pg, logs-postgrest and logs-mcp -- are excluded at ingest and never appear here at all. Every other namespace, including ssint-main-coding, is tailed in full and then cut down by the error filter. Host (node/systemd journal) records are not container log lines and never appear here; see logs_api.host.';
COMMENT ON COLUMN logs_api.entries.at IS
  'UTC timestamp the line was emitted, as recorded by the container runtime.';
COMMENT ON COLUMN logs_api.entries.namespace IS
  'Kubernetes namespace of the pod that emitted the line, e.g. cluster-main-observability.';
COMMENT ON COLUMN logs_api.entries.pod IS
  'Full pod name including the ReplicaSet/StatefulSet suffix, e.g. logs-postgrest-6d9f7c8b4-x2k9p.';
COMMENT ON COLUMN logs_api.entries.container IS
  'Container name within the pod. Pods with sidecars emit interleaved lines that are only separable by this column.';
COMMENT ON COLUMN logs_api.entries.stream IS
  'Either stdout or stderr. Many workloads log normal operation to stderr, so stderr alone is not an error signal.';
COMMENT ON COLUMN logs_api.entries.message IS
  'The log line itself, with the container-runtime framing already stripped.';
COMMENT ON COLUMN logs_api.entries.labels IS
  'The pod''s Kubernetes labels as captured at write time, e.g. {"app":"logs-mcp","entity":"cluster"}. Filter with PostgREST containment, ?labels=cs.{"app":"logs-mcp"}, which is index-backed. Null for lines written before label capture was enabled, and never backfilled: a pod''s labels today are not necessarily what they were when the line was emitted.';

CREATE OR REPLACE VIEW logs_api.host AS
SELECT
  l."time" AS at,
  l.node   AS node,
  l.unit   AS unit,
  l.message AS message
FROM public.logs l
WHERE l.tag LIKE 'host.%';

COMMENT ON VIEW logs_api.host IS
  'Host (node) journal lines, newest first when ordered by "at". This is not container output -- it is systemd journal entries read directly off each node, scoped at ingest to a small allowlist of units (bootc-update, k3s, kcluster-node-network, kcluster-provision, greenboot) chosen because they can explain a node failing to update or failing to come back afterward. Every other unit on the host journal is discarded before it reaches storage and was never captured -- an empty result here can mean either that an allowlisted unit was quiet, or that the question is about a unit outside the allowlist, which this store cannot answer regardless of the time window. Retention is 14 days, shared with the rest of public.logs. For a node''s current, unfiltered journal use the flux MCP against the node directly; this store has no shell-on-node equivalent and only ever holds what fluent-bit''s systemd input captured.';
COMMENT ON COLUMN logs_api.host.at IS
  'UTC timestamp the journal entry was written, per journald.';
COMMENT ON COLUMN logs_api.host.node IS
  'The node hostname the entry was read from, e.g. k-e7488b70. From journald''s HOSTNAME field.';
COMMENT ON COLUMN logs_api.host.unit IS
  'The systemd unit that logged the entry, e.g. bootc-update.service. From journald''s _SYSTEMD_UNIT field; always one of the allowlisted units, since anything else was dropped at ingest.';
COMMENT ON COLUMN logs_api.host.message IS
  'The journal entry text, from journald''s MESSAGE field.';

DROP FUNCTION IF EXISTS logs_api.recent(int, text, text, text, int);
DROP FUNCTION IF EXISTS logs_api.errors(int, text, int);
DROP FUNCTION IF EXISTS logs_api.search(text, int, text, int);
DROP FUNCTION IF EXISTS logs_api.pod_tail(text, int, text);
DROP FUNCTION IF EXISTS logs_api.volume(int);
DROP FUNCTION IF EXISTS logs_api.workloads(int);


CREATE OR REPLACE FUNCTION logs_api.recent(
  since_minutes    int       DEFAULT 15,
  namespace_filter text      DEFAULT NULL,
  pod_filter       text      DEFAULT NULL,
  container_filter text      DEFAULT NULL,
  stream_filter    text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL,
  max_rows         int       DEFAULT 200,
  oldest_first     boolean   DEFAULT false
) RETURNS TABLE (
  at timestamp, namespace text, pod text, container text,
  stream text, message text, labels jsonb
) LANGUAGE sql STABLE AS $recent$
  SELECT t.* FROM (
    SELECT l."time", l.namespace, l.pod, l.container, l.stream, l.message, l.labels
    FROM public.logs l
    WHERE l."time" >= COALESCE(
            since_time,
            COALESCE(until_time, now() AT TIME ZONE 'utc')
              - make_interval(mins => since_minutes),
            '-infinity'::timestamp)
      AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
      AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
      AND (pod_filter       IS NULL OR l.pod LIKE pod_filter || '%')
      AND (container_filter IS NULL OR l.container = container_filter)
      AND (stream_filter    IS NULL OR l.stream = stream_filter)
      AND logs_maint.label_match(l.labels, label_selector)
      AND l.tag NOT LIKE 'host.%'
    ORDER BY l."time" DESC
    LIMIT LEAST(max_rows, 1000)
  ) t (t_at, t_ns, t_pod, t_container, t_stream, t_message, t_labels)
  ORDER BY CASE WHEN oldest_first THEN t.t_at END ASC,
           CASE WHEN NOT oldest_first THEN t.t_at END DESC;
$recent$;

COMMENT ON FUNCTION logs_api.recent(int, text, text, text, text, text, timestamp, timestamp, int, boolean) IS
  'Most recent log lines across the cluster, newest first. The general-purpose replacement for `kubectl logs` when you want a live look at what is happening right now. Unlike kubectl logs this reads durable storage, so it still works for pods that have already been deleted. Time window: since_minutes counts back from now, or pass since_time/until_time as UTC timestamps ("2026-08-30T03:00:00") for an absolute window -- use those to re-examine a past incident, and as a cursor when polling. pod_filter matches as a prefix, so a Deployment name catches every replica. label_selector takes kubectl syntax: "app=nginx,tier!=canary", "app in (web,api)", "!debug". Set oldest_first to read the result in chronological order. This store retains error-signal lines only, not all container output. An empty result means no matching error-signal lines were recorded -- it does not mean the workload was silent, and it does not mean the pipeline is broken. To tell those apart, call workloads or volume: if they return rows, ingest is healthy. For a workload''s normal, unfiltered output use the flux MCP''s `get_kubernetes_logs` tool, which reads the live kubelet tail. The log pipeline''s own components -- fluent-bit, logs-pg, logs-postgrest and logs-mcp -- are excluded at ingest and never appear here at all. Every other namespace, including ssint-main-coding, is tailed in full and then cut down by the error filter.';

CREATE OR REPLACE FUNCTION logs_api.errors(
  since_minutes    int       DEFAULT 60,
  namespace_filter text      DEFAULT NULL,
  pod_filter       text      DEFAULT NULL,
  container_filter text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL,
  max_rows         int       DEFAULT 200,
  oldest_first     boolean   DEFAULT false
) RETURNS TABLE (
  at timestamp, namespace text, pod text, container text,
  stream text, message text, labels jsonb
) LANGUAGE sql STABLE AS $errors$
  SELECT t.* FROM (
    SELECT l."time", l.namespace, l.pod, l.container, l.stream, l.message, l.labels
    FROM public.logs l
    WHERE l."time" >= COALESCE(
            since_time,
            COALESCE(until_time, now() AT TIME ZONE 'utc')
              - make_interval(mins => since_minutes),
            '-infinity'::timestamp)
      AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
      AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
      AND (pod_filter       IS NULL OR l.pod LIKE pod_filter || '%')
      AND (container_filter IS NULL OR l.container = container_filter)
      AND logs_maint.label_match(l.labels, label_selector)
      AND l.message ~* '(error|fatal|panic|exception|traceback|segfault|fail(ed|ure)?)'
      AND l.tag NOT LIKE 'host.%'
    ORDER BY l."time" DESC
    LIMIT LEAST(max_rows, 1000)
  ) t (t_at, t_ns, t_pod, t_container, t_stream, t_message, t_labels)
  ORDER BY CASE WHEN oldest_first THEN t.t_at END ASC,
           CASE WHEN NOT oldest_first THEN t.t_at END DESC;
$errors$;

COMMENT ON FUNCTION logs_api.errors(int, text, text, text, text, timestamp, timestamp, int, boolean) IS
  'Log lines that look like failures, newest first. Start here when triaging "something is broken" without yet knowing which workload. Matching is a case-insensitive regex over the message text (error, fatal, panic, exception, traceback, segfault, fail/failed/failure), so it over-matches on lines that merely discuss errors and misses failures phrased in other words. Treat the result as a lead, not a verdict. Scope it with namespace_filter, pod_filter (prefix), container_filter or label_selector ("app=nginx,tier!=canary"); bound it with since_minutes, or since_time/until_time for an absolute UTC window. This store retains error-signal lines only, not all container output, so an empty result can mean either that nothing matched this function''s pattern or that no error-signal lines were ingested for the window at all -- either way it does not mean the workload was silent, and it does not mean the pipeline is broken. To tell those apart, call workloads or volume: if they return rows, ingest is healthy. For a workload''s normal, unfiltered output use the flux MCP''s `get_kubernetes_logs` tool, which reads the live kubelet tail. The log pipeline''s own components -- fluent-bit, logs-pg, logs-postgrest and logs-mcp -- are excluded at ingest and never appear here at all. Every other namespace, including ssint-main-coding, is tailed in full and then cut down by the error filter.';

CREATE OR REPLACE FUNCTION logs_api.search(
  pattern          text,
  since_hours      int       DEFAULT 24,
  namespace_filter text      DEFAULT NULL,
  pod_filter       text      DEFAULT NULL,
  container_filter text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL,
  max_rows         int       DEFAULT 200,
  oldest_first     boolean   DEFAULT false
) RETURNS TABLE (
  at timestamp, namespace text, pod text, container text,
  stream text, message text, labels jsonb
) LANGUAGE sql STABLE AS $search$
  SELECT t.* FROM (
    SELECT l."time", l.namespace, l.pod, l.container, l.stream, l.message, l.labels
    FROM public.logs l
    WHERE l."time" >= COALESCE(
            since_time,
            COALESCE(until_time, now() AT TIME ZONE 'utc')
              - make_interval(hours => since_hours),
            '-infinity'::timestamp)
      AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
      AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
      AND (pod_filter       IS NULL OR l.pod LIKE pod_filter || '%')
      AND (container_filter IS NULL OR l.container = container_filter)
      AND logs_maint.label_match(l.labels, label_selector)
      AND l.message ILIKE '%' || pattern || '%'
      AND l.tag NOT LIKE 'host.%'
    ORDER BY l."time" DESC
    LIMIT LEAST(max_rows, 1000)
  ) t (t_at, t_ns, t_pod, t_container, t_stream, t_message, t_labels)
  ORDER BY CASE WHEN oldest_first THEN t.t_at END ASC,
           CASE WHEN NOT oldest_first THEN t.t_at END DESC;
$search$;

COMMENT ON FUNCTION logs_api.search(text, int, text, text, text, text, timestamp, timestamp, int, boolean) IS
  'Full-text substring search across all captured log lines, newest first. Use this to trace a specific identifier -- a request id, a hostname, an error string, a git SHA -- across every workload at once, which is the thing kubectl logs fundamentally cannot do. Matching is case-insensitive substring, not regex or word-boundary. Narrow with namespace_filter, pod_filter (prefix), container_filter or label_selector ("app=nginx,tier!=canary"); bound with since_hours, or since_time/until_time for an absolute UTC window. "All captured log lines" means error-signal lines only, not all container output: an empty result means the pattern was not found among what was retained, not that it never occurred. To confirm ingest is healthy, call workloads or volume -- rows there mean the pipeline is working even when a search comes back empty. For a workload''s normal, unfiltered output use the flux MCP''s `get_kubernetes_logs` tool, which reads the live kubelet tail. The log pipeline''s own components -- fluent-bit, logs-pg, logs-postgrest and logs-mcp -- are excluded at ingest and never appear here at all. Every other namespace, including ssint-main-coding, is tailed in full and then cut down by the error filter.';

CREATE OR REPLACE FUNCTION logs_api.pod_tail(
  pod_name         text      DEFAULT NULL,
  namespace_filter text      DEFAULT NULL,
  container_filter text      DEFAULT NULL,
  stream_filter    text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_minutes    int       DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL,
  max_rows         int       DEFAULT 100,
  oldest_first     boolean   DEFAULT true
) RETURNS TABLE (
  at timestamp, namespace text, pod text, container text,
  stream text, message text, labels jsonb
) LANGUAGE sql STABLE AS $pod_tail$
  SELECT t.* FROM (
    SELECT l."time", l.namespace, l.pod, l.container, l.stream, l.message, l.labels
    FROM public.logs l
    WHERE l."time" >= COALESCE(
            since_time,
            COALESCE(until_time, now() AT TIME ZONE 'utc')
              - make_interval(mins => since_minutes),
            '-infinity'::timestamp)
      AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
      AND (pod_name         IS NULL OR l.pod LIKE pod_name || '%')
      AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
      AND (container_filter IS NULL OR l.container = container_filter)
      AND (stream_filter    IS NULL OR l.stream = stream_filter)
      AND logs_maint.label_match(l.labels, label_selector)
      AND l.tag NOT LIKE 'host.%'
    ORDER BY l."time" DESC
    LIMIT LEAST(max_rows, 1000)
  ) t (t_at, t_ns, t_pod, t_container, t_stream, t_message, t_labels)
  ORDER BY CASE WHEN oldest_first THEN t.t_at END ASC,
           CASE WHEN NOT oldest_first THEN t.t_at END DESC;
$pod_tail$;

COMMENT ON FUNCTION logs_api.pod_tail(text, text, text, text, text, int, timestamp, timestamp, int, boolean) IS
  'The last N lines from one pod, in chronological order -- the direct equivalent of `kubectl logs --tail`, but it still returns output for pods that no longer exist. Selection always takes the NEWEST max_rows lines; oldest_first only controls the order they are returned in, and defaults to true so a stack trace reads top to bottom as it would from kubectl. pod_name is matched as a prefix, so passing a Deployment name such as "logs-postgrest" returns lines from every replica and every past generation of it -- scope with namespace_filter when a name prefix is ambiguous across namespaces. pod_name may be omitted entirely if label_selector is given ("app=nginx,tier!=canary"), matching `kubectl logs -l`. Bound the window with since_minutes, or since_time/until_time as absolute UTC timestamps. Unlike kubectl logs --tail, this store retains error-signal lines only, not all container output: an empty result does not mean the pod produced nothing, and it does not mean the pipeline is broken. To tell those apart, call workloads or volume: if they return rows for this pod, ingest is healthy and the pod simply logged nothing that looked like an error. For the pod''s normal, unfiltered output use the flux MCP''s `get_kubernetes_logs` tool, which reads the live kubelet tail. The log pipeline''s own components -- fluent-bit, logs-pg, logs-postgrest and logs-mcp -- are excluded at ingest and never appear here at all. Every other namespace, including ssint-main-coding, is tailed in full and then cut down by the error filter.';

CREATE OR REPLACE FUNCTION logs_api.volume(
  since_hours      int       DEFAULT 24,
  namespace_filter text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL
) RETURNS TABLE (
  namespace text, container text, lines bigint, bytes bigint
) LANGUAGE sql STABLE AS $volume$
  SELECT l.namespace, l.container, count(*), sum(length(l.message))::bigint
  FROM public.logs l
  WHERE l."time" >= COALESCE(
          since_time,
          COALESCE(until_time, now() AT TIME ZONE 'utc')
            - make_interval(hours => since_hours),
          '-infinity'::timestamp)
    AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
    AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
    AND logs_maint.label_match(l.labels, label_selector)
    AND l.tag NOT LIKE 'host.%'
  GROUP BY l.namespace, l.container
  ORDER BY 3 DESC;
$volume$;

COMMENT ON FUNCTION logs_api.volume(int, text, text, timestamp, timestamp) IS
  'Log line and byte counts grouped by namespace and container, noisiest first. Answers "what is filling the log store" -- use it to decide what to add to the collector exclude list before growing the volume, and to sanity-check retention against disk. Narrow with namespace_filter or label_selector ("app=nginx"); bound with since_hours, or since_time/until_time for an absolute UTC window to compare a spike against a quiet baseline. This is also the way to confirm ingest is alive: any rows at all prove the pipeline is working end to end, which is what distinguishes a quiet cluster from a broken collector when the other endpoints come back empty. Counts reflect post-filter retained lines only, not total container output, and never include the log pipeline''s own components, which are excluded at ingest.';

CREATE OR REPLACE FUNCTION logs_api.workloads(
  since_hours      int       DEFAULT 1,
  namespace_filter text      DEFAULT NULL,
  label_selector   text      DEFAULT NULL,
  since_time       timestamp DEFAULT NULL,
  until_time       timestamp DEFAULT NULL
) RETURNS TABLE (
  namespace text, pod text, container text, last_seen timestamp, labels jsonb
) LANGUAGE sql STABLE AS $workloads$
  SELECT l.namespace, l.pod, l.container, max(l."time"),
         (array_agg(l.labels ORDER BY l."time" DESC))[1]
  FROM public.logs l
  WHERE l."time" >= COALESCE(
          since_time,
          COALESCE(until_time, now() AT TIME ZONE 'utc')
            - make_interval(hours => since_hours),
          '-infinity'::timestamp)
    AND l."time" <= COALESCE(until_time, 'infinity'::timestamp)
    AND (namespace_filter IS NULL OR l.namespace = namespace_filter)
    AND logs_maint.label_match(l.labels, label_selector)
    AND l.tag NOT LIKE 'host.%'
  GROUP BY l.namespace, l.pod, l.container
  ORDER BY 4 DESC;
$workloads$;

COMMENT ON FUNCTION logs_api.workloads(int, text, text, timestamp, timestamp) IS
  'Every namespace/pod/container that has logged in the window, most recently active first, with the labels each was carrying. Call this first to discover exact pod and container names -- and the label keys worth selecting on -- rather than guessing at them. Narrow with namespace_filter or label_selector ("app=nginx"); bound with since_hours, or since_time/until_time for an absolute UTC window to find what was running during a past incident. This is also the way to confirm ingest is alive: any rows at all prove the pipeline is working end to end, which is what distinguishes a quiet cluster from a broken collector when the other endpoints come back empty. A pod absent from this list retained nothing in the window, which for a healthy pod is the ordinary case rather than a fault. Coverage reflects post-filter retained lines only, not total container output, and never includes the log pipeline''s own components, which are excluded at ingest.';

GRANT USAGE ON SCHEMA public   TO logs_read;
GRANT USAGE ON SCHEMA logs_api TO logs_read;
GRANT SELECT ON public.logs    TO logs_read;
GRANT SELECT ON ALL TABLES     IN SCHEMA logs_api TO logs_read;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA logs_api TO logs_read;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA logs_maint FROM PUBLIC;
GRANT USAGE ON SCHEMA logs_maint TO logs_read;
GRANT EXECUTE ON FUNCTION logs_maint.label_match(jsonb, text) TO logs_read;

COMMIT;

NOTIFY pgrst, 'reload schema';
