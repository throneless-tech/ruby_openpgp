require_relative "../../lib/openpgp"
require "test/unit"

class TestKey < Test::Unit::TestCase
  def get_key_from_cert
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    cert.key_amalgamations(OpenPGP::StandardPolicy.new, 1587301934)
      .for_transport_encryption
      .to_a
      .first
      .key
  end

  def test_clone
    key = get_key_from_cert
    key_clone = key.clone
    assert_equal(key, key_clone)
  end

  def test_creation_time
    key = get_key_from_cert
    assert_equal(1578241752, key.creation_time)
  end

  def test_to_debug_s
    key = get_key_from_cert
    # because the key is memory-encrypted in the sequioa-debug-mode
    # and the password for memory-encryption is different everytime,
    # the debug string is not deterministic. so check only that
    # something is returned from the function.
    assert(key.to_debug_s)
  end

  def test_equal
    key = get_key_from_cert
    key_clone = key.clone
    assert(key == key_clone)
    assert(key.eql?(key_clone))
  end

  def test_fingerprint
    key = get_key_from_cert
    assert_equal('0230 5755 37E5 C7FA B37F  7DDB 31C0 3251 B71D FB40', key.fingerprint.to_s)
  end

  def test_into_key_pair
    key = get_key_from_cert
    assert(key.clone.into_key_pair)
  end

  def test_keyid
    key = get_key_from_cert
    assert_equal('31C0 3251 B71D FB40', key.keyid.to_s)
  end

  def test_public_key_algo
    key = get_key_from_cert
    assert_equal(18, key.public_key_algo)
  end

  def test_public_key_bits
    key = get_key_from_cert
    assert_equal(256, key.public_key_bits)
  end
end
