"""API Gateway protocol erratum exposes the corrected public contract."""
from peaso.checks import CHECKS
from peaso.checks.catalog import proposal_provenance_for
from peaso.checks import aws_apigateway_logging_source_correction as correction

def test_public_contract_names_protocol_and_observation_limits():
    check = next(c for c in CHECKS if c.id == correction.CHECK_ID)
    public = check.public()
    assert public["dependencies"] == ["http_api_stage", "rest_api_stage", "rest_api_method"]
    assert "WebSocket" in public["description"]
    from peaso.remediation import template
    assert "log delivery is unverified" in " ".join(template(check.id)["caveats"])
    assert "HTTP" in public["not_applicable_when"]
    assert public["source_correction"]["source_relationship"].startswith("Derived")
    provenance = proposal_provenance_for(check.id)
    assert provenance["signed_spec_status"] == "historical_superseded_for_this_check"
    assert provenance["source_correction"] == public["source_correction"]
    from tests.reviewed_guidance_presentation import assert_description_preserves_contract
    assert_description_preserves_contract(check.id)
