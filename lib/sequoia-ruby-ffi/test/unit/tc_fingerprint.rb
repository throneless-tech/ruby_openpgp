require_relative "../../lib/openpgp"
require "test/unit"

class TestFingerprint < Test::Unit::TestCase
  def test_from_hex
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    assert_equal(
      "D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD",
      fingerprint.to_s
    )
  end

  def test_from_bytes
    fingerprint = OpenPGP::Fingerprint.new_from_bytes(
      "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb" \
      "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    )
    assert_equal(
      "BBBB BBBB BBBB BBBB BBBB  BBBB BBBB BBBB BBBB BBBB",
      fingerprint.to_s
    )
  end

  def test_as_bytes
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    fingerprint2 = OpenPGP::Fingerprint.new_from_bytes(fingerprint.as_bytes)
    assert_equal(
      "D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD",
      fingerprint2.to_s
    )
  end

  def test_equal
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    fingerprint2 = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    assert_equal(fingerprint, fingerprint2)
    assert_true(fingerprint == fingerprint2)
    assert_true(fingerprint.eql?(fingerprint2))
  end

  def test_clone
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    fingerprint2 = fingerprint.clone
    assert_equal(
      "D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD",
      fingerprint2.to_s
    )
  end

  def test_to_debug_s
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    assert_equal(
      'Fingerprint("D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD")',
      fingerprint.to_debug_s
    )
  end

  def test_to_s
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    assert_equal(
      'D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD',
      fingerprint.to_s
    )
  end

  def test_hash
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    map = {}
    map[fingerprint] = 1
    fingerprint2 = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    map[fingerprint2] += 1
    assert_equal(2, map[fingerprint])
  end

  def test_to_keyid
    fingerprint = OpenPGP::Fingerprint.new_from_hex(
      "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    )
    keyid = OpenPGP::KeyId.new_from_hex("31855247603831FD")
    assert_equal(keyid, fingerprint.to_keyid)
  end

  def test_to_hex
    hex = "D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD"
    fingerprint = OpenPGP::Fingerprint.new_from_hex(hex)
    assert_equal(hex, fingerprint.to_hex)
  end
end
