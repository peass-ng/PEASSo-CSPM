"""Operation-specific location constraints for Dataplex lake listings."""

# lakes.list requires a Google Cloud region, unlike entryGroups, entryTypes
# and aspectTypes. Service-wide locations.list also advertises global and
# multi-region names. Exclude only these known non-regions from automatic
# discovery; retain new/private region names and let their API errors surface.
# https://docs.cloud.google.com/knowledge-catalog/docs/reference/rest/v1/projects.locations.lakes/list
# https://docs.cloud.google.com/firestore/native/docs/locations
LAKE_NON_REGIONAL_LOCATIONS = frozenset({'global', 'us', 'eu', 'asia', 'nam5', 'nam7', 'eur3'})
