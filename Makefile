APP_ENV = dev
CONSOLE_HANDLERS = address org scangroup user webdata
CR = supportprovision

build:
	$(foreach var,$(CONSOLE_HANDLERS),GOOS=linux go build -o dist/console/main ./api/console/$(var)/ && zip -j dist/console/$(var)_handler.zip dist/console/main && rm dist/console/main;)

buildcr:
	$(foreach var,$(CR),GOOS=linux go build -o dist/cr/main ./cr/$(var)/ && zip -j dist/cr/$(var)_handler.zip dist/cr/main && rm dist/cr/main;)

upload:
	aws s3 sync dist/console/ s3://linkai-infra/frontend/lambdas/console/

uploadcr:
	aws s3 sync dist/cr/ s3://linkai-infra/frontend/lambdas/cr/