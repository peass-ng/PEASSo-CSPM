"""Register the optional selected S3 source secret check and its native cases."""
from . import selected_admission


def install():
    from . import aws_s3_selected_source_secret_review_20261020 as reviewed
    declaration, = reviewed.DECLARATIONS
    cases = selected_admission.load_cases('aws_s3_selected_source_native_cases_20261020.json')
    selected_admission.install('aws', [(declaration, reviewed.evaluate)], cases, severity='high')
