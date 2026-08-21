package openssl

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSha1(t *testing.T) {
	src := "apple"
	dst := Sha1(src)
	assert.Equal(t, []byte{0xd0, 0xbe, 0x2d, 0xc4, 0x21, 0xbe, 0x4f, 0xcd, 0x1, 0x72, 0xe5, 0xaf, 0xce, 0xea, 0x39, 0x70, 0xe2, 0xf3, 0xd9, 0x40}, dst)
	assert.Equal(t, "d0be2dc421be4fcd0172e5afceea3970e2f3d940", Sha1ToString(src))
}

func TestHmacSha1(t *testing.T) {
	src := "apple"
	dst := HmacSha1("secret", src)
	assert.Equal(t, "2651783bdc7367acd2dde6f830ca0b7104368911", hex.EncodeToString(dst))
}

func TestHmacSha1ToString(t *testing.T) {
	src := "apple"
	dst := HmacSha1ToString("secret", src)
	assert.Equal(t, "2651783bdc7367acd2dde6f830ca0b7104368911", dst)
}

func TestSha224(t *testing.T) {
	src := "apple"
	dst := Sha224(src)
	assert.Equal(t, "b7bbfdf1a1012999b3c466fdeb906a629caa5e3e022428d1eb702281", hex.EncodeToString(dst))
	assert.Equal(t, "b7bbfdf1a1012999b3c466fdeb906a629caa5e3e022428d1eb702281", Sha224ToString(src))
}

func TestHmacSha224(t *testing.T) {
	dst := HmacSha224("secret", "apple")
	assert.Equal(t, "6612b1a347a167b10d664953966cb70c33c83ff4e8abc1413ebdc497", hex.EncodeToString(dst))
}

func TestHmacSha224ToString(t *testing.T) {
	dst := HmacSha224ToString("secret", "apple")
	assert.Equal(t, "6612b1a347a167b10d664953966cb70c33c83ff4e8abc1413ebdc497", dst)
}

func TestSha256(t *testing.T) {
	src := "apple"
	dst := Sha256(src)
	assert.Equal(t, "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", hex.EncodeToString(dst))
	assert.Equal(t, "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", Sha256ToString(src))
}

func TestHmacSha256(t *testing.T) {
	dst := HmacSha256("secret", "apple")
	assert.Equal(t, "37431003b2d14b6bddb9334c7ec2ff0ea0c65f96ec650952384e56cae83c398f", hex.EncodeToString(dst))
}

func TestHmacSha256ToString(t *testing.T) {
	dst := HmacSha256ToString("secret", "apple")
	assert.Equal(t, "37431003b2d14b6bddb9334c7ec2ff0ea0c65f96ec650952384e56cae83c398f", dst)
}

func TestSha384(t *testing.T) {
	src := "apple"
	dst := Sha384(src)
	assert.Equal(t, "3d8786fcb588c93348756c6429717dc6c374a14f7029362281a3b21dc10250ddf0d0578052749822eb08bc0dc1e68b0f", hex.EncodeToString(dst))
	assert.Equal(t, "3d8786fcb588c93348756c6429717dc6c374a14f7029362281a3b21dc10250ddf0d0578052749822eb08bc0dc1e68b0f", Sha384ToString(src))
}

func TestHmacSha384(t *testing.T) {
	dst := HmacSha384("secret", "apple")
	assert.Equal(t, "d2a847a311701d5871cbd5871f53baf23a038763836acfe4314897c9080b9af7cf349e8195bde1da11a517454ee22ddb", hex.EncodeToString(dst))
}

func TestHmacSha384ToString(t *testing.T) {
	dst := HmacSha384ToString("secret", "apple")
	assert.Equal(t, "d2a847a311701d5871cbd5871f53baf23a038763836acfe4314897c9080b9af7cf349e8195bde1da11a517454ee22ddb", dst)
}

func TestSha512(t *testing.T) {
	src := "apple"
	dst := Sha512(src)
	assert.Equal(t, "844d8779103b94c18f4aa4cc0c3b4474058580a991fba85d3ca698a0bc9e52c5940feb7a65a3a290e17e6b23ee943ecc4f73e7490327245b4fe5d5efb590feb2", hex.EncodeToString(dst))
	assert.Equal(t, "844d8779103b94c18f4aa4cc0c3b4474058580a991fba85d3ca698a0bc9e52c5940feb7a65a3a290e17e6b23ee943ecc4f73e7490327245b4fe5d5efb590feb2", Sha512ToString(src))
}

func TestHmacSha512(t *testing.T) {
	dst := HmacSha512("secret", "apple")
	assert.Equal(t, "33c2f1dbd0b93a8a8354ddb888df1ff97b986959d4d710280f66730a913dc9d4535c43a3d51b3c7ff3708355d3d75ab67a105221b8ca803ed4e604f13514b145", hex.EncodeToString(dst))
}

func TestHmacSha512ToString(t *testing.T) {
	dst := HmacSha512ToString("secret", "apple")
	assert.Equal(t, "33c2f1dbd0b93a8a8354ddb888df1ff97b986959d4d710280f66730a913dc9d4535c43a3d51b3c7ff3708355d3d75ab67a105221b8ca803ed4e604f13514b145", dst)
}
