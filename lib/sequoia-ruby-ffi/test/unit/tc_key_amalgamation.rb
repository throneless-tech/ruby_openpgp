require_relative "../../lib/openpgp"
require "test/unit"

class TestKeyAmalgamation < Test::Unit::TestCase
  def get_key_amalgamation_from_cert
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    cert.key_amalgamations(OpenPGP::StandardPolicy.new, 1587301934)
      .for_transport_encryption
      .to_a
      .first
  end

  def test_key
    ka = get_key_amalgamation_from_cert
    assert_equal('31C0 3251 B71D FB40', ka.key.keyid.to_s)
  end
end
