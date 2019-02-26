.DEFAULT_GOAL := deploy

clean:
	rm -rf ./src/site-packages || true
	rm handler.zip || true
	rm saml.out.template || true
	mkdir ./src/site-packages
.PHONY: clean

test: clean
	pip install -r requirements-dev.txt --target ./src/site-packages
	python -m unittest discover
	rm -rf ./src/site-packages || true
.PHONY: test


install: test
	pip install -r requirements.txt --target ./src/site-packages
.PHONY: install

package: install
	cd ./src && zip -r ../handler.zip .
	aws cloudformation package \
		--template-file sam.template \
		--output-template-file sam.out.template \
		--s3-bucket ${S3_BUCKET_NAME} \
		--s3-prefix cfn
.PHONY: package

deploy: package
	aws cloudformation deploy \
		--template-file sam.out.template \
		--capabilities CAPABILITY_IAM \
		--stack-name ${STACK_NAME} \
        --parameter-overrides \
        	AwsAssumeRoleName=${AWS_ASSUME_ROLE_NAME} \
			AwsAMLProviderName=${AWS_SAML_PROVIDER_NAME} \
			AzureObjectId=${AZURE_OBJECT_ID} \
			AzureTenantId=${AZURE_TENANT_ID} \
			AzureUsername=${AZURE_USERNAME} \
			AzurePassword=${AZURE_PASSWORD}
.PHONY: deploy