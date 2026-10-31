"""Register the selected inline CodeBuild buildspec secret check and its native cases."""
from . import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from . import selected_admission
from peaso.collectors import aws_codebuild_buildspec_runtime_20261020 as runtime

CASES = 'aws_codebuild_buildspec_runtime_cases_20261020.json'


def install():
    d = dict(consumer.DECLARATION, kind=runtime.KIND)
    cases = selected_admission.load_cases(CASES)
    selected_admission.install('aws', [(dict(d, id=runtime.CHECK), consumer.evaluate)], cases, severity='high')
