package constants

// This is set during compilation. See dockerfiles for usage
var Version = "latest"

//const ApplicationJson = ""

const InvalidClientSecret = "invalid client secret"

const TestSystemName = "Token Test"

const TokenEndpoint = "/token"

const HeaderApplicationJSON = "application/json"

const Application string = "ssas"

// Sets requesting SGA on admin endpoint requests into context
type CtxSGAKeyType string

const CtxSGAKey CtxSGAKeyType = "CtxSGAKey"

// Sets bool that allows skipping of SGA authorization checks
type CtxSGASkipAuthType string

const CtxSGASkipAuthKey CtxSGASkipAuthType = "CtxSGASkipAuthKey"
