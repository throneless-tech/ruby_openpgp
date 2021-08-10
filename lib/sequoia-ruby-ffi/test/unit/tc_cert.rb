require_relative "../../lib/openpgp"
require "test/unit"
require "stringio"

class TestCert < Test::Unit::TestCase
  def test_new_from_file
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    assert_equal(cert.fingerprint.to_s, 'B6EA 34B3 FEDF 6659 D6E5  5386 C69B 09B8 DCFB B3DC')
  end

  def test_new_from_bytes
    filepath = 'test/unit/data/keys/transport-encryption-test-key'
    file = File.open(filepath, 'rb')
    expected_fingerprint = OpenPGP::Cert.new_from_file(filepath).fingerprint
    cert = OpenPGP::Cert.new_from_bytes(file.read)
    assert_equal(expected_fingerprint, cert.fingerprint)
  end

  def test_keys
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    expected_keyids = [
      'C69B 09B8 DCFB B3DC',
      'B6DE 8FFF 5351 4C3B',
      '31C0 3251 B71D FB40'
    ]
    actual_keyids = []
    cert.key_amalgamations(OpenPGP::StandardPolicy.new, 1587301934).each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)
  end

  def test_serialize
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    buffer = StringIO.new
    writer = OpenPGP::IOWriter.new_from_callback(buffer)
    cert.serialize(writer)
    buffer.rewind
    serialized = OpenPGP::Cert.new_from_bytes(buffer.read)
    assert_equal(cert.fingerprint, serialized.fingerprint)
  end
end

class TestCertValidKeyIter < Test::Unit::TestCase
  def test_new_from_cert
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert, OpenPGP::StandardPolicy.new, 1582824411)
    expected_keyids = [
      'C69B 09B8 DCFB B3DC',
      'B6DE 8FFF 5351 4C3B',
      '31C0 3251 B71D FB40'
    ]
    actual_keyids = []
    keyiter.each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)
  end

  def test_secret_keys
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert, OpenPGP::StandardPolicy.new, 1582824411)
    expected_keyids = [
      'C69B 09B8 DCFB B3DC',
      'B6DE 8FFF 5351 4C3B',
      '31C0 3251 B71D FB40'
    ]
    actual_keyids = []
    keyiter.secret_keys.each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)

    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/foo-bar-transferable-public-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert, OpenPGP::StandardPolicy.new, 1582824411)
    keyiter.secret_keys.each do |ka|
      # unreachable
      assert false
    end
  end

  def test_for_signing
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert, OpenPGP::StandardPolicy.new, 1582824411)
    expected_keyids = ['B6DE 8FFF 5351 4C3B']
    actual_keyids = []
    keyiter.for_signing.each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)
  end

  def test_for_storage_encryption
    cert_with_storage = OpenPGP::Cert.new_from_file('test/unit/data/keys/storage-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert_with_storage, OpenPGP::StandardPolicy.new, 1582824411)
    expected_keyids = ['7A97 57DB 09F7 E57D']
    actual_keyids = []
    keyiter.for_storage_encryption.each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)

    cert_without_storage = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert_without_storage, OpenPGP::StandardPolicy.new, 1582824411)
    keyiter.for_storage_encryption.each do |ka|
      # unreachable
      assert false
    end
  end

  def test_for_transport_encryption
    cert_without_transport = OpenPGP::Cert.new_from_file('test/unit/data/keys/storage-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert_without_transport, OpenPGP::StandardPolicy.new, 1582824411)
    keyiter.for_transport_encryption.each do |ka|
      # unreachable
      assert false
    end

    cert_with_transport = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    keyiter = OpenPGP::CertValidKeyIter.new_from_cert(cert_with_transport, OpenPGP::StandardPolicy.new, 1582824411)
    expected_keyids = ['31C0 3251 B71D FB40']
    actual_keyids = []
    keyiter.for_transport_encryption.each do |ka|
      actual_keyids << ka.key.keyid.to_s
    end
    assert_equal(expected_keyids, actual_keyids)
  end
end
