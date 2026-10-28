"""Owned AWS Marketplace Catalog listing visibility, without entity content."""

ENTITY_TYPES = ("AmiProduct", "Audience", "BrandingSettings", "ContainerProduct", "DataProduct",
                "Experience", "MachineLearningProduct", "Offer", "OfferSet", "ProcurementPolicy",
                "ResaleAuthorization", "SaaSProduct", "Seller", "Solution")
KIND = "marketplace_entity"
SPECS = {KIND: ("marketplace-catalog", "list_entities", "EntitySummaryList")}
NATIVE_IDS = {KIND: "EntityArn"}
GLOBAL_TYPES = {KIND}
READ_ACTIONS = {("marketplace-catalog", "list_entities")}


def collect(requests, session, region, account):
    from .aws import ReadResult

    selected = getattr(session, "region_name", None) or "us-east-1"
    partition = session.get_partition_for_region(selected)
    home = {"aws": "us-east-1", "aws-cn": "cn-north-1", "aws-us-gov": "us-gov-west-1"}.get(partition)
    if home is None:
        return ReadResult([], "not_supported", {"code": "marketplace_partition_unreviewed"})
    rows, failures = [], []
    for entity_type in ENTITY_TYPES:
        listed = requests.pages(session, "marketplace-catalog", home, "list_entities", "EntitySummaryList",
                                Catalog="AWSMarketplace", EntityType=entity_type, OwnershipType="SELF")
        if listed.status not in {"collected", "empty"}:
            failures.append(listed.status)
        for item in listed.items:
            if not isinstance(item, dict):
                failures.append("malformed")
                continue
            arn = item.get("EntityArn")
            prefix = f"arn:{partition}:aws-marketplace:{home}:{account}:AWSMarketplace/{entity_type}/"
            if not isinstance(arn, str) or not arn.startswith(prefix) or not arn[len(prefix):]:
                failures.append("malformed")
                continue
            summary = item.get(f"{entity_type}Summary")
            visibility = summary.get("Visibility", item.get("Visibility")) if isinstance(summary, dict) else item.get("Visibility")
            if visibility is not None and not isinstance(visibility, str):
                failures.append("malformed")
                continue
            row = {"EntityArn": arn, "EntityType": entity_type, "Visibility": visibility}
            if entity_type == "Offer" and isinstance(summary, dict):
                buyers = summary.get("BuyerAccounts", [])
                if not isinstance(buyers, list) or any(not isinstance(buyer, str) or
                                                       len(buyer) != 12 or not buyer.isdecimal() for buyer in buyers):
                    failures.append("malformed")
                    continue
                row.update(State=summary.get("State"), BuyerAccounts=buyers)
            if entity_type == "ResaleAuthorization" and isinstance(summary, dict):
                row.update(Status=summary.get("Status"), ResellerAccountId=summary.get("ResellerAccountID"))
            rows.append(row)
    return ReadResult(rows, "partial" if rows and failures else failures[0] if failures else
                      "collected" if rows else "empty",
                      {"code": "marketplace_entity_inventory_incomplete"} if failures else None)


FETCHERS = {KIND: collect}
