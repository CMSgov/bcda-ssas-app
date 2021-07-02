module github.com/CMSgov/bcda-ssas-app

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.1-0.20180309185540-3c771ce311b7+incompatible
	github.com/go-chi/chi v4.0.3-0.20190508141739-08c92af09aaf+incompatible
	github.com/go-chi/render v1.0.1
	github.com/lib/pq v1.6.0
	github.com/newrelic/go-agent/v3 v3.13.0
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pborman/uuid v0.0.0-20180122190007-c65b2f87fee3
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	gopkg.in/macaroon.v2 v2.1.0
	gorm.io/driver/postgres v1.0.6
	gorm.io/gorm v1.20.8
)

replace (
	github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v3.2.1-0.20180309185540-3c771ce311b7+incompatible
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
