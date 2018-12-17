APP_ENV = dev
CONSOLE_HANDLERS = auth address org scangroup user webdata

build:
	$(foreach var,$(CONSOLE_HANDLERS),GOOS=linux go build -o dist/console/main ./api/console/$(var)/ && zip -j dist/console/$(var)_handler.zip dist/console/main && rm dist/console/main;)

buildauth:
	GOOS=linux go build -o dist/console/main ./api/console/auth/ && zip -j dist/console/auth_handler.zip dist/console/main && rm dist/console/main

buildauthorizer:
	GOOS=linux go build -o dist/authorizer/main ./api/authorizer/ && zip -j dist/authorizer/lambda_authorizer.zip dist/authorizer/main && rm dist/authorizer/main

buildorg:
	GOOS=linux go build -o dist/console/main ./api/console/org/ && zip -j dist/console/org_handler.zip dist/console/main && rm dist/console/main

provision:
	docker build -t linkai_support_org_provision -f Dockerfile.support_org_provision .

upload:
	aws s3 sync dist/console/ s3://linkai-infra/frontend/lambdas/console/

uploadauthorizer:
	aws s3 sync dist/authorizer/ s3://linkai-infra/frontend/lambdas/authorizer/

deployorg: buildorg upload
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/console/org_handler.zip --function-name dev-console-handler-orgservice

deployauthorizer: buildauthorizer uploadauthorizer
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/authorizer/lambda_authorizer.zip --function-name dev-console-handler-lambda-authorizer

deployauth: buildauth upload
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/console/auth_handler.zip --function-name dev-console-handler-auth

uploadprovision: provision
	docker tag linkai_support_org_provision:latest 447064213022.dkr.ecr.us-east-1.amazonaws.com/support_org_provision:latest && docker push 447064213022.dkr.ecr.us-east-1.amazonaws.com/support_org_provision:latest