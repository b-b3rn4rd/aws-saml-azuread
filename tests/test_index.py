import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.realpath(__file__))+'/../src/site-packages'))

import unittest
import src.index as lambda_handler
import botocore.session
from botocore.stub import Stubber
from datetime import datetime
import json
import boto3
from mock import patch
from mock import call
from azure.graphrbac.models.app_role import AppRole
from azure.graphrbac.models.service_principal import ServicePrincipal
import uuid


class TestHandler(unittest.TestCase):

    @patch.dict(os.environ, {
        'AWS_ASSUME_ROLE_NAME': 'OrganizationAccountAccessRole',
        'AWS_SAML_PROVIDER_NAME': 'azuread',
        'AZURE_USERNAME': 'user@example.com',
        'AZURE_PASSWORD': 'my_password',
        'AZURE_TENANT_ID': '1111-2222-3333-4444-55555',
        'AZURE_OBJECT_ID': '1111-2222-3333-4444-55555',
    })
    @patch('src.index.boto3')
    @patch('src.index.UserPassCredentials')
    @patch('src.index.GraphRbacManagementClient')
    def test_HandlerHappyPath(self, graph_rbnac_client_mock, user_pass_creds_mock, boto3_mock):
        list_accounts_response = {
            'Accounts': [
                {
                    'Id': '123456789123',
                    'Arn': 'arn:aws:organizations::111111111111:account/o-exampleorgid/123456789123',
                    'Email': 'account-one@examp.ecom',
                    'Name': 'account-one',
                    'Status': 'ACTIVE',
                    'JoinedMethod': 'CREATED',
                    'JoinedTimestamp': datetime(2015, 1, 1)
                },
            ],

        }

        assume_role_response = {
            'Credentials': {
                'AccessKeyId': 'ASIAJEXAMPLEXEG2JICEA',
                'SecretAccessKey': '9drTJvcXLB89EXAMPLELB8923FB892xMFI',
                'SessionToken': 'AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=',
                'Expiration': datetime(2015, 1, 1)
            },
            'AssumedRoleUser': {
                'AssumedRoleId': 'AROA3XFRBF535PLBIFPI4:assume_role_session',
                'Arn': 'arn:aws:sts::123456789123:assumed-role/OrganizationAccountAccessRole/assume_role_session'
            }
        }

        assume_role_request = {
            'RoleArn': 'arn:aws:iam::123456789123:role/OrganizationAccountAccessRole',
            'RoleSessionName': 'assume_role_session',
        }

        list_roles_response = {
            'Roles': [
                {
                    'Path': '/',
                    'RoleName': 'saml_role',
                    'RoleId': 'AROAJ52OTH4H7LEXAMPLE',
                    'Arn': 'arn:aws:iam::123456789123:role/saml_role',
                    'CreateDate': datetime(2015, 1, 1),
                    'AssumeRolePolicyDocument': json.dumps({
                        'Statement': [
                            {
                                'Principal': {
                                    'Federated': 'arn:aws:iam::123456789123:saml-provider/azuread'
                                }
                            }
                        ]
                    }),
                    'Description': 'string',
                    'MaxSessionDuration': 3600,
                },
                {
                    'Path': '/',
                    'RoleName': 'nonsaml_role',
                    'RoleId': 'AROAJ52OTH4H7LEXAMPLE',
                    'Arn': 'arn:aws:iam::123456789123:role/nonsaml_role',
                    'CreateDate': datetime(2015, 1, 1),
                    'AssumeRolePolicyDocument': json.dumps({
                        'Statement': [
                        ]
                    }),
                    'Description': 'string',
                    'MaxSessionDuration': 3600,
                },
            ]
        }

        stubber_org = Stubber(lambda_handler.client_organizations)
        stubber_org.add_response('list_accounts', list_accounts_response, {})
        stubber_org.activate()

        stubber_sts = Stubber(lambda_handler.client_sts)
        stubber_sts.add_response('assume_role', assume_role_response, assume_role_request)
        stubber_sts.activate()

        client_iam = boto3.client('iam')
        stubber_iam = Stubber(client_iam)
        stubber_iam.add_response('list_roles', list_roles_response, {})
        stubber_iam.activate()

        boto3_mock.client.return_value = client_iam

        service_principal = ServicePrincipal(**{
            'app_roles': [
                AppRole(**{
                    'description': 'msiam_access',
                    'display_name': 'msiam_access',
                    'allowed_member_types': ['User', ],
                    'id': uuid.uuid4(),
                    'is_enabled': True,
                    'value': 'msiam_access',
                }),
                AppRole(**{
                    'description': 'old_role',
                    'display_name': 'old_role',
                    'allowed_member_types': ['User', ],
                    'id': uuid.uuid4(),
                    'is_enabled': True,
                    'value': 'old_role',
                }),
            ]
        })

        graph_rbnac_client_mock.return_value.service_principals.get.return_value = service_principal

        lambda_handler.handler({}, {})

        self.assertEqual(graph_rbnac_client_mock.return_value.service_principals.update.call_count, 2)

        expected_calls = [
            call('1111-2222-3333-4444-55555', service_principal),
            call('1111-2222-3333-4444-55555', service_principal)
        ]

        graph_rbnac_client_mock.return_value.service_principals.update.assert_has_calls(expected_calls)
        stubber_org.assert_no_pending_responses()
        stubber_sts.assert_no_pending_responses()
        stubber_iam.assert_no_pending_responses()

