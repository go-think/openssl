package openssl

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	TestBlockSize10 = 10
	TestBlockSize20 = 20
	TestBlockSize30 = 30
)

func TestKeyGenerator(t *testing.T) {
	testData := []byte("test")
	result10 := KeyGenerator(testData, TestBlockSize10)
	result20 := KeyGenerator(testData, TestBlockSize20)
	testCases := []struct {
		data      []byte
		blockSize int
		expected  []byte
	}{
		{testData, TestBlockSize10, result10},
		{testData, TestBlockSize20, result20},
		{testData, TestBlockSize30, []byte("test")},
	}

	for _, tc := range testCases {
		result := KeyGenerator(tc.data, tc.blockSize)
		assert.Equal(t, tc.expected, result, "KeyGenerator output should match expected key")
	}
}

func TestRandomBytes(t *testing.T) {
	testLengths := []int{12, 16, 24, 32, 64}
	for _, length := range testLengths {
		b1, err := RandomBytes(length)
		assert.NoError(t, err)
		assert.Equal(t, length, len(b1))

		b2, err := RandomBytes(length)
		assert.NoError(t, err)
		assert.Equal(t, length, len(b2))

		// 确保多次生成的内容具有随机性（不相同）
		assert.False(t, bytes.Equal(b1, b2), "consecutive random bytes of length %d should not be equal", length)
	}

	// 边界与异常测试
	invalidLengths := []int{0, -1, -10}
	for _, length := range invalidLengths {
		b, err := RandomBytes(length)
		assert.Error(t, err)
		assert.Nil(t, b)
	}
}