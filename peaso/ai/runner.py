"""Bounded Chack review in a private working directory.

No scan credentials enter prompts, argv or process environment. Only their file
format and path are described. Parent handles timeouts and descendant cleanup.
"""
import json
import os
import sys
import time
from pathlib import Path


def validate_runtime(authentication, relay):
    from .providers import ModelAccess, ConfigurationError, model_access, validate_access
    if relay:
        import requests
        try:
            with requests.Session() as session:
                session.trust_env = False
                with session.get(relay + '/validate', headers={'Authorization': 'Bearer ' + authentication['access_token']},
                                 allow_redirects=False, timeout=(5, 35)) as response:
                    if response.status_code != 200 or response.json() != {'valid': True}:
                        raise ConfigurationError('AI configuration preflight failed.')
        except Exception:
            raise ConfigurationError('AI configuration preflight failed.') from None
    else:
        access = ModelAccess(authentication['provider'], authentication['model'], authentication['thinking'], authentication['access_token']) if authentication.get('model') else model_access(authentication['access_token'])
        validate_access(access)


def output_text(result):
    """Keep SDK structured output as JSON across Chack's string formatter.

    Pinned Chack's OpenRouter SDK returns a dict in run1_output, then applies
    str() when building output. Serialize the original object; never evaluate
    Python-looking model text or discard a changed/budget-warning response.
    """
    output = result.output
    if isinstance(output, dict):
        return json.dumps(output)
    for field in ('run2_output', 'run1_output'):
        native = getattr(result, field, None)
        if isinstance(native, dict) and output == str(native):
            return json.dumps(native)
    return output


def main():
    started = time.monotonic()
    stage = sys.argv[1]
    if stage not in ('network', 'priorities'):
        raise ValueError('unknown_ai_stage')
    root = Path.cwd()
    if stage == 'priorities':
        from .briefing import materialize_context
        materialize_context(root)
    from chack_agent import Chack, load_config
    from .prompting import access_instructions, agent_config_path
    auth_path = root / 'codex-auth.json'
    authentication = json.loads(auth_path.read_text())
    auth_path.unlink()
    entries = json.loads((root / 'credentials.json').read_text())['entries']
    config = load_config(str(agent_config_path(stage)))
    from .deadline import configure_runner
    configure_runner(config)
    config.env = {'CHACK_EXEC_CWD': str(root)}
    relay = os.getenv('PEASO_AI_MODEL_RELAY')
    if relay:
        from .codex_relay_cli import relay_origin
        relay = relay_origin(relay)
    validate_runtime(authentication, relay)
    from .providers import configure_agent
    configure_agent(config, authentication, relay=relay)
    if relay and authentication.get('provider', 'codex') in {'codex', 'openai'}:
        # Chack writes a fresh CODEX_HOME, so enforce routing through the CLI
        # wrapper rather than hoping its generated config preserves our keys.
        wrapper = root / 'relay-codex'
        wrapper.write_text('#!' + sys.executable + '\nfrom peaso.ai.codex_relay_cli import main\nmain()\n')
        wrapper.chmod(0o700)
        os.environ['CODEX_PATH'] = str(wrapper)
        os.environ['PEASO_AI_CODEX_AUTH'] = authentication.get('provider', 'codex')
        path = '/openai/v1' if authentication.get('provider') == 'openai' else '/codex'
        config.env.update(OPENAI_BASE_URL=relay + path, CHACK_CODEX_DIRECT_CACHE_TRANSPORT='off')
    from .deadline import ENVIRONMENT_KEY, timeout_seconds
    from .output_validation import context, validate, feedback, private_file, InvalidAgentOutput, MAX_OUTPUT
    original = context(stage, root)
    budget = timeout_seconds(os.getenv(ENVIRONMENT_KEY, str(config.agent.max_runtime_minutes * 60)))
    end = started + budget
    text = ''
    for attempt in range(2):
        if attempt:
            validate_runtime(authentication, relay)
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        configure_runner(config, remaining=remaining)
        result = Chack(config).run(
            'cspm-' + stage, text, exec_cwd=str(root),
            prompt_variables_override={'access_instructions': access_instructions(entries)},
        )
        if getattr(result, 'error', None):
            raise RuntimeError('agent_failed')
        output = output_text(result)
        if len(output.encode('utf-8')) > MAX_OUTPUT:
            raise InvalidAgentOutput('agent_output_limit')
        data = None
        try:
            data = json.loads(output)
            validate(stage, data, original)
        except ValueError as error:
            if attempt:
                raise InvalidAgentOutput('invalid_agent_result') from None
            private_file(root/'candidate-output.json', data if data is not None else
                         {'unparsed_output': output[:100000]})
            private_file(root/'validation-feedback.json', feedback(error))
            text = ('Correct candidate-output.json using validation-feedback.json. Both files and all original '
                    'inputs are in the working directory. Resolve references against original findings/resources '
                    'with the supplied local reader. Preserve confirmed facts and uncertainty; return the complete '
                    'requested JSON with valid references, ranks and field limits. Use only read-only access.\n\n'
                    '### AVAILABLE ACCESS\n' + access_instructions(entries))
            continue
        private_file(root/'result.json', data)
        return



def entrypoint():
    from .output_validation import InvalidAgentOutput
    from .providers import ConfigurationError
    try:
        main()
    except TimeoutError:
        return 124
    except InvalidAgentOutput:
        return 65
    except ConfigurationError:
        return 78
    return 0


if __name__ == '__main__':
    sys.exit(entrypoint())
