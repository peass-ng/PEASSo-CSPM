"""WorkDocs users are listed per directory: IAM-signed DescribeUsers needs an organizationId."""
from peaso.collectors import aws_facts_ext
from peaso.collectors.aws import ReadResult

ACCOUNT, REGION, DIRECTORY = '123456789012', 'us-east-1', 'd-0123456789'


class Requests:
    max_items = None

    def __init__(self, directories):
        self.directories, self.calls = directories, []

    def pages(self, session, service, region, operation, key, **arguments):
        self.calls.append((service, operation, arguments))
        if operation == 'describe_directories':
            return ReadResult(self.directories, 'collected' if self.directories else 'empty')
        if operation == 'describe_users':
            if arguments.get('OrganizationId') != DIRECTORY:
                return ReadResult([], 'unknown', {'code': 'ValidationException'})
            return ReadResult([{'RootFolderId': 'root-folder'}], 'collected')
        if operation == 'describe_resource_permissions':
            return ReadResult([{'Id': 'reviewer', 'Type': 'USER', 'Roles': [{'Role': 'OWNER', 'Type': 'DIRECT'}]}], 'collected')
        return ReadResult([], 'empty')


def test_region_without_directories_has_no_workdocs_shares():
    requests = Requests([])
    read = aws_facts_ext._workdocs_document_shares(requests, None, REGION, ACCOUNT)
    assert read.status == 'empty'
    assert not any(operation == 'describe_users' for _, operation, _ in requests.calls)


def test_users_are_listed_with_their_directory_as_organization():
    requests = Requests([{'DirectoryId': DIRECTORY}])
    read = aws_facts_ext._workdocs_document_shares(requests, None, REGION, ACCOUNT)
    assert read.status == 'collected'
    assert [item['id'] for item in read.items] == ['root-folder']
