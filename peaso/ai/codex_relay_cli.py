"""Force the pinned Codex executable to use the private HTTP model relay."""
import os
import shutil
import sys
from urllib.parse import urlsplit


def relay_origin(value):
    parsed = urlsplit(value or '')
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port
            or value != 'http://127.0.0.1:' + str(parsed.port)):
        raise RuntimeError('model_relay_required')
    return value


def main():
    base = relay_origin(os.environ.get('PEASO_AI_MODEL_RELAY'))
    binary = shutil.which('codex')
    if not binary:
        raise RuntimeError('codex_unavailable')
    # Chack supplies exec-level --config values. Put these last in that same
    # subcommand: clap's exec overrides otherwise replace root-level config.
    api_key = os.environ.get('PEASO_AI_CODEX_AUTH') == 'openai'
    route = '/openai/v1' if api_key else '/codex'
    args = [binary, *sys.argv[1:], '--config', 'model_provider="cspm-relay"',
            '--config', 'model_providers.cspm-relay.name="CSPM isolated relay"',
            '--config', 'model_providers.cspm-relay.base_url="' + base + route + '"',
            '--config', 'model_providers.cspm-relay.wire_api="responses"',
            '--config', 'model_providers.cspm-relay.requires_openai_auth=' + ('false' if api_key else 'true'),
            '--config', 'model_providers.cspm-relay.supports_websockets=false',
            '--config', 'chatgpt_base_url="' + base + '"',
            # The working directory holds scanned-account data: never load its AGENTS.md.
            '--config', 'project_doc_max_bytes=0']
    if api_key:
        args += ['--config', 'model_providers.cspm-relay.env_key="OPENAI_API_KEY"']
    os.execv(binary, args)
