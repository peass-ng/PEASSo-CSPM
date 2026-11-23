from io import BytesIO
import re

from pypdf import PdfReader

from peaso.server.findings_pdf import PROJECT_URL, render_findings_pdf


def finding(title, severity, count, **overrides):
    return dict(dict(
        title=title, severity=severity, status="confirmed", kind="vulnerability",
        description="The captured configuration permits access.",
        impact="Unrestricted access to assessment resources.",
        recommendation="Restrict the role.",
        verification="Read back the role.",
        services=["IAM"], affected_assets=[f"test-{severity}-asset-{i:03}" for i in range(count)],
    ), **overrides)


def urls(page):
    return [annotation.get_object().get("/A", {}).get("/URI")
            for annotation in page.get("/Annots", ()) if annotation.get_object().get("/A")]


def test_report_pdf_orders_findings_and_paginates_without_shrinking_or_repeating_titles():
    high = finding("Standing write access", "high", 25, recommendation="Check the role. " * 1100)
    low = finding("Broad read access", "low", 26)
    raw = render_findings_pdf(
        name="Combined · Tenant A", generated_at=1785258645, summary="Validated findings.",
        issues=[low, high], scopes=[{"name": "Production", "provider": "AWS", "scopes": ["us-east-1"]}],
    )
    report = PdfReader(BytesIO(raw))
    pages = [re.sub(r" +", " ", page.extract_text()) for page in report.pages]
    first = next(i for i, page in enumerate(pages) if "OBSERVED ISSUE" in page)
    high_start, low_start = [i for i, page in enumerate(pages) if "OBSERVED ISSUE" in page]
    assert first == high_start and low_start > high_start + 1
    assert "Standing write access" in pages[high_start]
    assert all("Standing write access" not in page and "/ CONTINUED" in page
               for page in pages[high_start + 1:low_start])
    high_text = "\n".join(pages[high_start:low_start])
    assert high_text.count("Check the role.") == 1100
    assert all(f"test-high-asset-{i:03}" in high_text for i in range(25))
    assert "Broad read access" in pages[low_start]
    assert all(f"test-low-asset-{i:03}" in pages[low_start] for i in range(10))
    assert "test-low-asset-010" not in pages[low_start]
    assert "16 additional affected assets." in pages[low_start]
    assert "Report Generated" in pages[0] and "Combined" not in pages[0]
    assert "us-east-1" in "\n".join(pages)
    assert all(urls(page) and set(urls(page)) == {PROJECT_URL} for page in report.pages)
    assert len(urls(report.pages[-1])) == 4
    assert "Thank you for using" in pages[-1]
    assert report.outline[-1]["/Title"] == "Thank you"


def test_pdf_links_the_product_but_ignores_user_supplied_links_and_images():
    report = PdfReader(BytesIO(render_findings_pdf(
        name="Tenant A", generated_at=None, summary="", scopes=[],
        issues=[finding("Noisy report", "low", 0, description=(
            "See PEASS'o CSPM and [remote](https://example.invalid). "
            "![asset](https://example.invalid/asset.png)"
        ))],
    )))
    issue_page = next(page for page in report.pages if "OBSERVED ISSUE" in page.extract_text())
    assert urls(issue_page) == [PROJECT_URL, PROJECT_URL]
    assert "No directly affected assets" in issue_page.extract_text()
