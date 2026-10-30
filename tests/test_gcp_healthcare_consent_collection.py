"""Native Healthcare inventory follows the dataset and consent-store hierarchy."""
import pytest

from test_gcp_config_delivery_location import catalog


PROJECT = "projects/demo-project1"
LOCATION = PROJECT + "/locations/us-central1"
DATASET = LOCATION + "/datasets/clinical"
STORE = DATASET + "/consentStores/research"
FHIR_STORE = DATASET + "/fhirStores/patients"
DICOM_STORE = DATASET + "/dicomStores/images"
HL7V2_STORE = DATASET + "/hl7V2Stores/messages"
ROOT = "https://healthcare.googleapis.com/v1"


class Collector:
    def __init__(self, consent_store=STORE):
        self.consent_store = consent_store
        self.fhir_store = FHIR_STORE
        self.dicom_store = DICOM_STORE
        self.hl7v2_store = HL7V2_STORE
        self.urls = []

    def pages(self, url, scope, *, key=None, single=False, params=None, transform=None):
        # Mirrors GCPCollector.pages, which projects each row before yielding it.
        for rows, receipt in self._pages(url, scope, key=key, single=single, params=params):
            yield ([transform(row) for row in rows] if transform else rows), receipt

    def _pages(self, url, scope, *, key=None, single=False, params=None):
        self.urls.append(url)
        assert scope == PROJECT
        if single:
            yield [{"name": url.removeprefix(ROOT + "/")}], url
        elif url == ROOT + "/" + PROJECT + "/locations":
            yield [{"name": LOCATION}], url
        elif url == ROOT + "/" + LOCATION + "/datasets":
            yield [{"name": DATASET}], url
        elif url == ROOT + "/" + DATASET + "/consentStores":
            yield [{"name": self.consent_store}], url
        elif url == ROOT + "/" + DATASET + "/fhirStores":
            yield [{"name": self.fhir_store}], url
        elif url == ROOT + "/" + DATASET + "/dicomStores":
            yield [{"name": self.dicom_store}], url
        elif url == ROOT + "/" + DATASET + "/hl7V2Stores":
            yield [{"name": self.hl7v2_store}], url
        else:
            raise AssertionError(url)

    def hydrate(self, item, field, url, scope, *, params=None):
        self.urls.append(url)
        assert field == "iamPolicy"
        assert params == {"options.requestedPolicyVersion": 3}
        return {**item, "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}


def test_dataset_and_consent_store_policies_are_read_at_exact_resources():
    module = catalog()
    collector = Collector()
    datasets = list(module.inventory_pages(collector, PROJECT,
                    module.PRIVATE_SERVICES["healthcare_dataset"], PROJECT, ROOT))
    assert datasets[-1][0][0]["name"] == DATASET
    stores = list(module.inventory_pages(collector, PROJECT,
                  module.PRIVATE_SERVICES["healthcare_consent_store"], PROJECT, ROOT))
    assert stores[-1][0][0]["name"] == STORE
    assert ROOT + "/" + DATASET + ":getIamPolicy" in collector.urls
    assert ROOT + "/" + STORE + ":getIamPolicy" in collector.urls


def test_fhir_store_and_policy_are_read_under_the_exact_dataset():
    module = catalog()
    collector = Collector()
    stores = list(module.inventory_pages(collector, PROJECT,
                  module.PRIVATE_SERVICES["healthcare_fhir_store"], PROJECT, ROOT))
    assert stores[-1][0][0]["name"] == FHIR_STORE
    assert ROOT + "/" + FHIR_STORE + ":getIamPolicy" in collector.urls


def test_dicom_store_and_policy_are_read_under_the_exact_dataset():
    module = catalog()
    collector = Collector()
    stores = list(module.inventory_pages(collector, PROJECT,
                  module.PRIVATE_SERVICES["healthcare_dicom_store"], PROJECT, ROOT))
    assert stores[-1][0][0]["name"] == DICOM_STORE
    assert ROOT + "/" + DICOM_STORE + ":getIamPolicy" in collector.urls


def test_hl7v2_store_and_policy_are_read_under_the_exact_dataset():
    module = catalog()
    collector = Collector()
    stores = list(module.inventory_pages(collector, PROJECT,
                  module.PRIVATE_SERVICES["healthcare_hl7v2_store"], PROJECT, ROOT))
    assert stores[-1][0][0]["name"] == HL7V2_STORE
    assert ROOT + "/" + HL7V2_STORE + ":getIamPolicy" in collector.urls


def test_store_from_another_dataset_is_rejected():
    module = catalog()
    def read_error_init(self, status, reason):
        self.status = status
        self.reason = reason
    module.ReadError.__init__ = read_error_init
    collector = Collector(STORE.replace("/datasets/clinical/", "/datasets/other/"))
    with pytest.raises(module.ReadError):
        list(module.inventory_pages(collector, PROJECT,
             module.PRIVATE_SERVICES["healthcare_consent_store"], PROJECT, ROOT))
