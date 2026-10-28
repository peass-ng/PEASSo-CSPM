"""Bounded, pre-cache projection of OpenSearch Ingestion sink destinations."""

from urllib.parse import urlsplit


_LOCAL_PROCESSORS = frozenset({
    "add_entries", "aggregate", "anomaly_detector", "convert_entry_type", "copy_values",
    "csv", "date", "delay", "decompress", "delete_entries", "dissect", "drop_events",
    "flatten", "geoip", "grok", "key_value", "list_to_map", "lowercase_string",
    "map_to_list", "mutate_event", "mutate_string", "obfuscate", "otel_metrics",
    "otel_trace_group", "otel_trace", "parse_ion", "parse_json", "parse_xml",
    "rename_keys", "select_entries", "service_map", "split_event", "split_string",
    "string_converter", "substitute_string", "trace_peer_forwarder", "translate",
    "trim_string", "truncate", "uppercase_string", "user_agent", "write_json",
})


def _host(value):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        url = urlsplit(value if "://" in value else "https://" + value)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.port not in (None, 443)):
            return None
    except ValueError:
        return None
    return url.hostname.lower()


def project_sinks(config):
    """Return only destination hosts/buckets; never return YAML or credentials."""
    if not isinstance(config, str) or len(config) > 1_000_000:
        return {"status": "unresolved", "targets": []}
    import yaml
    from yaml.events import AliasEvent

    class LimitedLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.node_count = 0

        def compose_node(self, parent, index):
            self.node_count += 1
            if self.node_count > 10000 or self.check_event(AliasEvent):
                raise ValueError("osis_yaml_complexity")
            return super().compose_node(parent, index)

    try:
        config = yaml.load(config, Loader=LimitedLoader)
    except (yaml.YAMLError, ValueError, RecursionError):
        return {"status": "unresolved", "targets": []}
    if not isinstance(config, dict):
        return {"status": "unresolved", "targets": []}
    targets, incomplete, found = set(), False, False

    def bucket(value):
        nonlocal incomplete
        if isinstance(value, str) and 3 <= len(value) <= 63 and all(c.isalnum() or c in '.-' for c in value):
            targets.add(("bucket", value))
        else:
            incomplete = True

    for name, pipeline in config.items():
        if name == "version":
            continue
        if not isinstance(pipeline, dict) or not isinstance(pipeline.get("sink"), list):
            incomplete = True
            continue
        processors = pipeline.get("processor", [])
        if not isinstance(processors, list):
            incomplete = True
            processors = []
        for processor in processors:
            if not isinstance(processor, dict) or len(processor) != 1:
                incomplete = True
                continue
            plugin, options = next(iter(processor.items()))
            if plugin in _LOCAL_PROCESSORS:
                continue
            if not isinstance(options, dict):
                incomplete = True
                continue
            if plugin == "aws_lambda":
                function = options.get("function_name")
                if isinstance(function, str) and function.startswith("arn:"):
                    targets.add(("lambda", function))
                elif not isinstance(function, str) or not function:
                    incomplete = True
            else:
                incomplete = True
            output_path = options.get("output_path")
            if isinstance(output_path, str) and output_path.startswith("s3://"):
                bucket(output_path[5:].split("/", 1)[0])
            dlq = options.get("dlq")
            if isinstance(dlq, dict) and "s3" in dlq:
                s3 = dlq["s3"]
                bucket(s3.get("bucket") if isinstance(s3, dict) else None)
        for sink in pipeline["sink"]:
            if not isinstance(sink, dict) or len(sink) != 1:
                incomplete = True
                continue
            plugin, options = next(iter(sink.items()))
            if plugin == "pipeline":
                continue
            found = True
            if not isinstance(options, dict):
                incomplete = True
                continue
            if plugin == "s3":
                bucket(options.get("bucket"))
            elif plugin == "opensearch":
                hosts = options.get("hosts")
                if not isinstance(hosts, list) or not hosts:
                    incomplete = True
                else:
                    for url in hosts:
                        host = _host(url)
                        if host:
                            targets.add(("host", host))
                        else:
                            incomplete = True
                dlq = options.get("dlq")
                if isinstance(dlq, dict) and "s3" in dlq:
                    s3 = dlq["s3"]
                    bucket(s3.get("bucket") if isinstance(s3, dict) else None)
            elif plugin == "prometheus":
                host = _host(options.get("url"))
                if host:
                    targets.add(("host", host))
                else:
                    incomplete = True
            else:
                incomplete = True
    if not found:
        incomplete = True
    return {"status": "partial" if incomplete else "collected",
            "targets": [{"type": kind, "value": value} for kind, value in sorted(targets)]}
