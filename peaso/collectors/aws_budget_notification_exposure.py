"""Budget notification recipients, projected before snapshot storage."""
import re

KIND = "budget_notification_recipients"
SPECS = {KIND: ("budgets", "describe_budgets", "Budgets")}
GLOBAL_TYPES = {KIND}
NATIVE_IDS = {KIND: "BudgetName"}
READ_ACTIONS = {("budgets", "describe_notifications_for_budget"),
                ("budgets", "describe_subscribers_for_notification")}
_EMAIL = re.compile(r"[^@\s]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\Z")
_SNS = re.compile(r"arn:aws(?:-us-gov|-cn)?:sns:[a-z0-9-]+:[0-9]{12}:[^:]+\Z")


def collect(requests, session, region, account):
    from .aws import ReadResult

    budgets = requests.pages(session, "budgets", region, "describe_budgets", "Budgets", AccountId=account)
    if budgets.status not in ("collected", "empty"):
        return ReadResult([], budgets.status, budgets.error)
    rows, seen, failures = [], set(), []
    for budget in budgets.items:
        name = budget.get("BudgetName") if isinstance(budget, dict) else None
        if not isinstance(name, str) or not name or name in seen:
            failures.append("malformed_budget_identity")
            continue
        seen.add(name)
        notifications = requests.pages(session, "budgets", region, "describe_notifications_for_budget",
                                       "Notifications", AccountId=account, BudgetName=name)
        if notifications.status not in ("collected", "empty"):
            failures.append("notification_list_unavailable")
            continue
        domains, topics, malformed = set(), set(), False
        for notification in notifications.items:
            if not isinstance(notification, dict) or any(key not in notification for key in
                                                        ("NotificationType", "ComparisonOperator", "Threshold")):
                malformed = True
                continue
            # The subscriber lookup requires the complete native Notification
            # shape, but the threshold itself is never retained in the snapshot.
            selector = {key: notification[key] for key in
                        ("NotificationType", "ComparisonOperator", "Threshold", "ThresholdType", "NotificationState")
                        if key in notification}
            subscribers = requests.pages(session, "budgets", region, "describe_subscribers_for_notification",
                                         "Subscribers", AccountId=account, BudgetName=name, Notification=selector)
            if subscribers.status not in ("collected", "empty"):
                malformed = True
                continue
            for subscriber in subscribers.items:
                kind = subscriber.get("SubscriptionType") if isinstance(subscriber, dict) else None
                address = subscriber.get("Address") if isinstance(subscriber, dict) else None
                if kind == "EMAIL" and isinstance(address, str) and (match := _EMAIL.fullmatch(address)):
                    domains.add(match.group(1).lower())
                elif kind == "SNS" and isinstance(address, str) and _SNS.fullmatch(address):
                    topics.add(address)
                else:
                    malformed = True
        if malformed:
            failures.append("subscriber_projection_incomplete")
        rows.append({"BudgetName": name, "AccountId": account,
                     "EmailDomains": sorted(domains), "SNSTopicArns": sorted(topics),
                     "RecipientCollectionStatus": "partial" if malformed else "collected"})
    status = "partial" if failures and rows else "malformed" if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": failures[0]} if failures else None)


FETCHERS = {KIND: collect}
