// Copyright 2021 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
