require_relative "../../lib/openpgp"
require "test/unit"

class TestReader < Test::Unit::TestCase
  def test_verify
    source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/signed-1-sha256-testy.gpg")

    public_keys_called = false
    get_public_keys = ->(keyids) do
      assert keyids
      public_keys_called = true
      [OpenPGP::Cert.new_from_file("test/unit/data/keys/testy.pgp")]
    end

    check_called = false
    check = ->(message_structure) do
      assert message_structure
      check_called = true
      PGP_STATUS_SUCCESS
    end

    reader = OpenPGP::Reader.new(source, get_public_keys, check, 1554542219, OpenPGP::StandardPolicy.new)
    reader = reader.verify

    content = reader.read(40)
    assert_equal(content, "A Cypherpunk's Manifesto\nby Eric Hughes\n")
    assert public_keys_called
    assert check_called
  end

  def test_verify_detached
    source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/a-cypherpunks-manifesto.txt")
    signature = OpenPGP::IOReader.new_from_file("test/unit/data/messages/a-cypherpunks-manifesto.txt.ed25519.sig")

    public_keys_called = false
    get_public_keys = ->(keyids) do
      assert keyids
      public_keys_called = true
      [OpenPGP::Cert.new_from_file("test/unit/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")]
    end

    check_called = false
    check = ->(message_structure) do
      assert message_structure
      check_called = true
      PGP_STATUS_SUCCESS
    end

    reader = OpenPGP::DetachedReader.new(signature, get_public_keys, check, 1554542219, OpenPGP::StandardPolicy.new)
    valid = reader.verify(source)

    assert_equal(valid.to_s, 'Success')
    assert public_keys_called
    assert check_called
  end

  def test_decrypt
    source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/encrypted-to-testy.gpg")

    cert = OpenPGP::Cert.new_from_file("test/unit/data/keys/testy-private.pgp")

    policy = OpenPGP::StandardPolicy.new
    time = 1554542219

    public_keys_called = false
    get_public_keys = ->(keyids) do
      assert keyids
      public_keys_called = true
      [cert]
    end

    check_called = false
    check = ->(message_structure) do
      assert message_structure
      check_called = true
      PGP_STATUS_SUCCESS
    end

    session_key_called = false
    get_session_key = ->(pkesks, skesks) do
      assert pkesks
      assert skesks
      session_key_called = true

      key = cert.key_amalgamations(policy, time).secret_keys.to_a[1].key
      sk, algo = pkesks[0].decrypt(key)
      return sk, algo, key.fingerprint
    end

    reader = OpenPGP::Reader.new(source, get_public_keys, check, time, policy)
    reader = reader.decrypt(get_session_key, nil)

    assert_equal(reader.read, "Test, 1-2-3.\n")
    assert public_keys_called
    assert check_called
    assert session_key_called
  end
end
