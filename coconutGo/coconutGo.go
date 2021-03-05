package coconutGo

import (
	"errors"
	"math/big"
)

// TODO: or fp.Element?

type Attribute = big.Int

var (
	ErrZeroThreshold = errors.New("tried to generate threshold keys with a 0 threshold value")

	ErrInvalidThreshold = errors.New("tried to generate threshold keys for threshold value being higher than number of the signing authorities")

	ErrPrepareBlindSignNoPrivate = errors.New("tried to prepare blind sign request for an empty set of private attributes")

	ErrPrepareBlindSignTooManyAttributes = errors.New("tried to prepare blind sign request for higher than specified in setup number of attributes")

	ErrBlindSignTooManyAttributes = errors.New("tried to perform blind sign for higher than specified in setup number of attributes")

	ErrBlindSignProof = errors.New("failed to verify the proof of knowledge")

	ErrProveNoPrivate = errors.New("tried to prove a credential with an empty set of private attributes")

	ErrProveTooManyAttributes = errors.New("tried to prove a credential for higher than supported by the provided verification key number of attributes")

	ErrInterpolationEmpty = errors.New("tried to perform lagrangian interpolation for an empty set of coordinates")

	ErrInterpolationIncomplete = errors.New("tried to perform lagrangian interpolation for an incomplete set of coordinates")

	ErrAggregationEmpty = errors.New("tried to aggregate an empty set of values")

	ErrDifferentSizeKeyAggregation = errors.New("tried to aggregate verification keys of different lengths")

	ErrAggregationNonUniqueIndices = errors.New("tried to perform aggregation on a set of non-unique indices")
)
