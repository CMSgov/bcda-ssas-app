module github.com/CMSgov/bcda-ssas-app

go 1.18

require (
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/render v1.0.1
	github.com/golang-jwt/jwt/v4 v4.4.2
	github.com/lib/pq v1.10.6
	github.com/newrelic/go-agent/v3 v3.17.0
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pborman/uuid v1.2.1
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	gopkg.in/macaroon.v2 v2.1.0
	gorm.io/driver/postgres v1.3.8
	gorm.io/gorm v1.23.8
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/frankban/quicktest v1.11.3 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.3 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	golang.org/x/net v0.0.0-20220708220712-1185a9018129 // indirect
	golang.org/x/sys v0.0.0-20220712014510-0a85c31ab51e // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220714211235-042d03aeabc9 // indirect
	google.golang.org/grpc v1.48.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace (
	github.com/go-chi/chi => github.com/go-chi/chi v4.0.3-0.20190508141739-08c92af09aaf+incompatible
	github.com/go-chi/render => github.com/go-chi/render v1.0.1
	github.com/lib/pq => github.com/lib/pq v0.0.0-20180523175426-90697d60dd84
	github.com/patrickmn/go-cache => github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pborman/uuid => github.com/pborman/uuid v0.0.0-20180122190007-c65b2f87fee3
	github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify => github.com/stretchr/testify v1.2.3-0.20181002233221-2db35c88b92a
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20190426145343-a29dc8fdc734
	gorm.io/driver/postgres => gorm.io/driver/postgres v0.2.4
	gorm.io/gorm => gorm.io/gorm v1.20.8
)
