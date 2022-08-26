module github.com/CMSgov/bcda-ssas-app

go 1.18

require (
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/render v1.0.2
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/lib/pq v1.10.6
	github.com/newrelic/go-agent/v3 v3.18.1
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pborman/uuid v1.2.1
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220824171710-5757bc0c5503
	gopkg.in/macaroon.v2 v2.1.0
	gorm.io/driver/postgres v1.3.9
	gorm.io/gorm v1.23.8
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.0.0-20220822230855-b0a4917ee28c // indirect
	golang.org/x/sys v0.0.0-20220825204002-c680a09ffe64 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220822174746-9e6da59bd2fc // indirect
	google.golang.org/grpc v1.49.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/go-chi/render => github.com/go-chi/render v1.0.1
	github.com/lib/pq => github.com/lib/pq v0.0.0-20180523175426-90697d60dd84
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20190426145343-a29dc8fdc734
	gorm.io/driver/postgres => gorm.io/driver/postgres v0.2.4
	gorm.io/gorm => gorm.io/gorm v1.20.8
)
