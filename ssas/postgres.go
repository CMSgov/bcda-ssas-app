package ssas

var repository Repository

// Repository contains all of the CRUD methods represented in the models package from the storage layer
type Repository interface {
	cclfFileRepository
	cclfBeneficiaryRepository
	suppressionRepository
	suppressionFileRepository
	jobRepository
	JobKeyRepository
	alr
}
