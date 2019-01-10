APP_ENV = dev
CONSOLE_HANDLERS = auth address org scangroup user webdata

build:
	$(foreach var,$(CONSOLE_HANDLERS),GOOS=linux go build -o dist/console/main ./api/console/$(var)/ && zip -j dist/console/$(var)_handler.zip dist/console/main && rm dist/console/main;)

# Authentication
buildauth:
	GOOS=linux go build -o dist/console/main ./api/console/auth/ && zip -j dist/console/auth_handler.zip dist/console/main && rm dist/console/main

deployauth: buildauth upload
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/console/auth_handler.zip --function-name dev-console-handler-auth

# Lambda Authorizer
buildauthorizer:
	GOOS=linux go build -o dist/authorizer/main ./api/authorizer/ && zip -j dist/authorizer/lambda_authorizer.zip dist/authorizer/main && rm dist/authorizer/main

uploadauthorizer:
	aws s3 sync dist/authorizer/ s3://linkai-infra/frontend/lambdas/authorizer/

deployauthorizer: buildauthorizer uploadauthorizer
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/authorizer/lambda_authorizer.zip --function-name dev-console-handler-lambda-authorizer

# Static Contents Authorizer
buildstaticauthorizer:
	GOOS=linux go build -o dist/staticauthorizer/main ./api/staticauthorizer/ && zip -j dist/staticauthorizer/static_authorizer.zip dist/staticauthorizer/main && rm dist/staticauthorizer/main

uploadstaticauthorizer: 
	aws s3 sync dist/staticauthorizer/ s3://linkai-infra/frontend/lambdas/staticauthorizer/

deploystaticauthorizer: buildstaticauthorizer uploadstaticauthorizer
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/staticauthorizer/static_authorizer.zip --function-name dev-console-handler-static-authorizer

# Admin features 
buildadmin:
	GOOS=linux go build -o dist/console/admin/main ./api/console/admin/ && zip -j dist/console/admin/admin_handler.zip dist/console/admin/main && rm dist/console/admin/main

uploadadmin: buildadmin
	aws s3 sync dist/console/admin s3://linkai-infra/frontend/lambdas/console/admin/

deployadmin:
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/console/admin/admin_handler.zip --function-name dev-console-handler-admin

# Support Provision
supportprovision:
	docker build -t support_org_provision -f Dockerfile.support_org_provision .

pushsupportprovision: supportprovision
	docker tag support_org_provision:latest 447064213022.dkr.ecr.us-east-1.amazonaws.com/support_org_provision:latest && docker push 447064213022.dkr.ecr.us-east-1.amazonaws.com/support_org_provision:latest

upload:
	aws s3 sync dist/console/ s3://linkai-infra/frontend/lambdas/console/

# Organization Handler
buildorg:
	GOOS=linux go build -o dist/console/main ./api/console/org/ && zip -j dist/console/org_handler.zip dist/console/main && rm dist/console/main

deployorg: buildorg upload
	aws lambda update-function-code --s3-bucket linkai-infra --s3-key frontend/lambdas/console/org_handler.zip --function-name dev-console-handler-orgservice