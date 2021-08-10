require_relative "../../lib/openpgp"
require "test/unit"

class TestKeyId < Test::Unit::TestCase
  def test_from_hex
    keyid = OpenPGP::KeyId.new_from_hex("bbbbbbbbbbbbbbbb")
    assert_equal("BBBB BBBB BBBB BBBB", keyid.to_s)
  end

  def test_from_bytes
    keyid = OpenPGP::KeyId.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    assert_equal("BBBB BBBB BBBB BBBB", keyid.to_s)
  end

  def test_clone
    keyid = OpenPGP::KeyId.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    keyid2 = keyid.clone
    assert_equal("BBBB BBBB BBBB BBBB", keyid2.to_s)
  end

  def test_equal
    keyid = OpenPGP::KeyId.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    keyid2 = OpenPGP::KeyId.new_from_hex("bbbbbbbbbbbbbbbb")
    assert_equal(keyid, keyid2)
    assert_true(keyid == keyid2)
    assert_true(keyid.eql?(keyid2))
  end

  def test_to_debug_s
    keyid = OpenPGP::KeyId.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    assert_equal('KeyID("BBBB BBBB BBBB BBBB")', keyid.to_debug_s)
  end

  def test_to_s
    keyid = OpenPGP::KeyId.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    assert_equal('BBBB BBBB BBBB BBBB', keyid.to_s)
  end

  def test_to_hex
    keyid = OpenPGP::KeyId.new_from_hex("bbbbbbbbbbbbbbbb")
    assert_equal("bbbbbbbbbbbbbbbb", keyid.to_hex.downcase)
  end

  def test_hash
    keyid = OpenPGP::KeyId.new_from_hex("bbbbbbbbbbbbbbbb")
    map = {}
    map[keyid] = 1
    keyid2 = keyid.clone
    map[keyid2] += 1
    assert_equal(2, map[keyid])
  end
end
