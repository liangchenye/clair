// Copyright 2015 clair authors
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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComparePriority(t *testing.T) {
	assert.Equal(t, Medium.Compare(Medium), 0, "Priority comparison failed")
	assert.True(t, Medium.Compare(High) < 0, "Priority comparison failed")
	assert.True(t, Critical.Compare(Low) > 0, "Priority comparison failed")
}

func TestIsValid(t *testing.T) {
	assert.False(t, Priority("Test").IsValid())
	assert.True(t, Unknown.IsValid())
}

func TestScoreToPriority(t *testing.T) {
	assert.Equal(t, ScoreToPriority(-1.0), Unknown)
	assert.Equal(t, ScoreToPriority(0.5), Negligible)
	assert.Equal(t, ScoreToPriority(2.0), Low)
	assert.Equal(t, ScoreToPriority(5.0), Medium)
	assert.Equal(t, ScoreToPriority(7.0), High)
	assert.Equal(t, ScoreToPriority(9.0), Critical)
	assert.Equal(t, ScoreToPriority(12.0), Unknown)
}
