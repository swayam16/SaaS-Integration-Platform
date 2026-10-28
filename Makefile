# SyncBridge - common tasks
PY ?= python3
STACK ?= syncbridge
REGION ?= us-east-1

.PHONY: install lint test chaos dev console lambda deploy reload clean

install:            ## Python package + console dependencies
	$(PY) -m pip install -e ".[dev]"
	cd console && npm ci

lint:               ## ruff, type check of the console, CloudFormation lint
	ruff check src tests
	ruff format --check src tests
	cd console && npm run typecheck
	cfn-lint infra/template.yaml

test:               ## unit, integration and end-to-end tests (no cloud accounts needed)
	pytest -q
	cd console && npm test

chaos:              ## the 10,000-case failure test, with the naive baseline for comparison
	syncbridge chaos --cases 10000 --seed 7 --baseline --strict

dev: console        ## local stack on http://localhost:8080 (console, simulators, mock Okta)
	syncbridge dev --port 8080

console:            ## build the admin console into console/dist
	cd console && npm run build

lambda:             ## Lambda package for arm64 / Python 3.12 into build/lambda
	rm -rf build/lambda && mkdir -p build/lambda
	$(PY) -m pip install --quiet --target build/lambda --platform manylinux2014_aarch64 \
		--implementation cp --python-version 3.12 --only-binary=:all: --upgrade \
		httpx "lxml>=5.2" "signxml>=4.0" "cryptography>=43" "pyjwt>=2.9"
	cp -r src/syncbridge build/lambda/
	find build/lambda -name "__pycache__" -prune -exec rm -rf {} +

deploy: lambda console   ## needs AWS SAM CLI and credentials; see docs/setup-guide.md
	sam deploy --template-file infra/template.yaml --stack-name $(STACK) --region $(REGION) \
		--capabilities CAPABILITY_IAM --resolve-s3 \
		--parameter-overrides DomainName=$(DOMAIN) CertificateArn=$(CERT_ARN) AlarmEmail=$(ALARM_EMAIL)
	aws s3 sync console/dist s3://$$(aws cloudformation describe-stacks --stack-name $(STACK) \
		--region $(REGION) --query "Stacks[0].Outputs[?OutputKey=='ConsoleBucketName'].OutputValue" \
		--output text) --delete
	aws cloudfront create-invalidation --paths "/*" --distribution-id $$(aws cloudformation \
		describe-stacks --stack-name $(STACK) --region $(REGION) \
		--query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue" --output text)

reload:             ## apply edited settings in Secrets Manager (starts fresh Lambda containers)
	for fn in $$(aws cloudformation describe-stack-resources --stack-name $(STACK) --region $(REGION) \
		--query "StackResources[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId" --output text); do \
		aws lambda update-function-configuration --region $(REGION) --function-name $$fn \
			--description "settings reloaded $$(date -u +%FT%TZ)" > /dev/null && echo "reloaded $$fn"; done

clean:
	rm -rf build console/dist .pytest_cache
