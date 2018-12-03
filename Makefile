APP_ENV = dev
CONSOLE_HANDLERS = address org scangroup user webdata


build:
	$(foreach var,$(CONSOLE_HANDLERS),GOOS=linux go build -o dist/console/$(var)_handler.zip ./api/console/$(var)/;)

upload:
	aws s3 sync dist/console/ s3://linkai-infra/frontend/lambdas/console/