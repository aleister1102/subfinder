package subscraping

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
)

const MultipleKeyPartsLength = 2

var sourceKeyIndices sync.Map // map[string]*atomic.Uint64

// PickRandom returns a key from v for sourceName using thread-safe round-robin rotation.
// When multiple keys are configured, it cycles through them sequentially across calls.
func PickRandom[T any](v []T, sourceName string) T {
	var result T
	length := len(v)
	if length == 0 {
		gologger.Debug().Msgf("Cannot use the %s source because there was no API key/secret defined for it.", sourceName)
		return result
	}
	if length == 1 {
		return v[0]
	}

	val, _ := sourceKeyIndices.LoadOrStore(sourceName, new(atomic.Uint64))
	counter := val.(*atomic.Uint64)
	idx := counter.Add(1) - 1
	return v[idx%uint64(length)]
}

// KeyRotator manages sequential rotation across a slice of keys.
type KeyRotator[T any] struct {
	keys    []T
	current atomic.Uint64
}

// NewKeyRotator initializes a KeyRotator with the provided keys.
func NewKeyRotator[T any](keys []T) *KeyRotator[T] {
	return &KeyRotator[T]{keys: keys}
}

// Next returns the next key in the pool using round-robin rotation.
func (kr *KeyRotator[T]) Next() (T, bool) {
	var zero T
	if len(kr.keys) == 0 {
		return zero, false
	}
	idx := kr.current.Add(1) - 1
	return kr.keys[idx%uint64(len(kr.keys))], true
}

// Total returns the number of keys managed.
func (kr *KeyRotator[T]) Total() int {
	return len(kr.keys)
}

func CreateApiKeys[T any](keys []string, provider func(k, v string) T) []T {
	var result []T
	for _, key := range keys {
		if keyPartA, keyPartB, ok := createMultiPartKey(key); ok {
			result = append(result, provider(keyPartA, keyPartB))
		}
	}
	return result
}

func createMultiPartKey(key string) (keyPartA, keyPartB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = len(parts) == MultipleKeyPartsLength

	if ok {
		keyPartA = parts[0]
		keyPartB = parts[1]
	}

	return
}
