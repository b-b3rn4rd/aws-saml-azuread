import os
import sys

sys.path.insert(0, os.path.abspath('./site-packages'))
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import UserPassCredentials
from azure.graphrbac.models.app_role import AppRole
import boto3
import uuid
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

client_organizations = boto3.client('organizations')
client_sts = boto3.client('sts')
client_iam = boto3.client('iam')


def handler(event, context):
    saml_available_roles = []
    paginator_list_account = client_organizations.get_paginator('list_accounts')

    for accounts_page in paginator_list_account.paginate():
        for aws_account in accounts_page['Accounts']:
            role_arn = 'arn:aws:iam::{}:role/{}'.format(aws_account['Id'], os.environ['AWS_ASSUME_ROLE_NAME'])
            provider_arn = 'arn:aws:iam::{}:saml-provider/{}'.format(aws_account['Id'], os.environ['AWS_SAML_PROVIDER_NAME'])

            try:
                logger.info('assuming role {}'.format(role_arn))
                assumed_role = client_sts.assume_role(RoleArn=role_arn, RoleSessionName="assume_role_session")
            except Exception as e:
                logger.exception('failed assuming role {}, skipping account {}'.format(role_arn, aws_account['Name']))
                continue

            credentials = assumed_role['Credentials']

            client_iam = boto3.client('iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            try:
                paginator_list_roles = client_iam.get_paginator('list_roles')

                for roles_page in paginator_list_roles.paginate():
                    roles = roles_page['Roles']
                    logger.info('discovered {} roles in {} account'.format(len(roles), aws_account['Name']))

                    for role in roles:
                        for statement in role['AssumeRolePolicyDocument']['Statement']:
                            if 'Federated' in statement['Principal'] and statement['Principal']['Federated'] == provider_arn:
                                label = '[{}] {}'.format(aws_account['Name'], role['RoleName'])
                                logger.info('role {} is for SAML'.format(label))

                                saml_available_roles.append(AppRole(**{
                                    'description': role['Description'] if 'Description' in role else role['RoleName'],
                                    'display_name': label,
                                    'allowed_member_types': ['User',],
                                    'id': uuid.uuid5(uuid.NAMESPACE_DNS, label),
                                    'is_enabled': True,
                                    'value': '{},{}'.format(role['Arn'], provider_arn),
                                }))
            except Exception as (e):
                logger.exception('failed inspecting roles(s), skipping account {}'.format(aws_account['Name']))
                continue

    if not saml_available_roles:
        logger.warning('there are no roles for SAML, check if roles principal matches provider arn')
        return

    credentials = UserPassCredentials(os.environ['AZURE_USERNAME'], os.environ['AZURE_PASSWORD'], resource='https://graph.windows.net')
    graphrbac_client = GraphRbacManagementClient(credentials, os.environ['AZURE_TENANT_ID'])

    try:
        principal = graphrbac_client.service_principals.get(object_id=os.environ['AZURE_OBJECT_ID'])
        for role in principal.app_roles:
            if role.description == 'msiam_access':
                saml_available_roles.insert(0, role)
                continue
            role.is_enabled = False

        logger.info('new roles are: {}'.format(saml_available_roles))

        logger.info('disabling existing roles {}'.format(principal.app_roles))
        graphrbac_client.service_principals.update(os.environ['AZURE_OBJECT_ID'], principal)
        principal.app_roles = saml_available_roles
        logger.info('creating new roles {}'.format(principal.app_roles))
        graphrbac_client.service_principals.update(os.environ['AZURE_OBJECT_ID'], principal)

    except Exception as (e):
        logger.exception('error while updating azure principal')


if __name__ == '__main__':
    handler({}, {})