require_relative "../../lib/openpgp"
require "test/unit"
require "stringio"

class TestSerialize < Test::Unit::TestCase
  def get_recipients_from_cert(cert, policy, time)
    recipients = []
    cert.key_amalgamations(policy, time)
      .for_transport_encryption
      .for_storage_encryption
      .each do |ka|
      recipient = OpenPGP::Recipient.new_from_key(ka.key)
      recipients << recipient
    end
    recipients
  end

  def get_signers_from_cert(cert, policy, time)
    sigs = []
    cert.key_amalgamations(policy, time)
      .secret_keys
      .for_signing
      .each do |ka|
      sigs << ka.key.clone.into_key_pair.as_signer
    end
    sigs
  end

  def test_arbitrary
    buffer = StringIO.new
    sink = OpenPGP::IOWriter.new_from_callback(buffer)
    writer = OpenPGP::WriterStack.new_message(sink)
    writer.arbitrary(OpenPGP::Tag.new(PGP_TAG_LITERAL))
    writer.write_all("Hello world!")
    writer.finalize
    buffer.rewind
    assert buffer.read
  end

  def test_literal
    buffer = StringIO.new
    sink = OpenPGP::IOWriter.new_from_callback(buffer)
    writer = OpenPGP::WriterStack.new_message(sink)
    writer.literal
    writer.write_all("Hello world!")
    writer.finalize
    buffer.rewind
    assert buffer.read
  end

  def test_encrypt
    buffer = StringIO.new
    sink = OpenPGP::IOWriter.new_from_callback(buffer)
    writer = OpenPGP::WriterStack.new_message(sink)
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    recipients = get_recipients_from_cert(cert, OpenPGP::StandardPolicy.new, 1587301934)
    passwords = ['p', 'f']

    writer.encrypt(passwords, recipients, 9, 0)
    writer.literal
    writer.write_all("Hello world!")
    writer.finalize
    buffer.rewind
    assert buffer.read
  end

  def test_sign
    buffer = StringIO.new
    sink = OpenPGP::IOWriter.new_from_callback(buffer)
    writer = OpenPGP::WriterStack.new_message(sink)
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    sigs = get_signers_from_cert(cert, OpenPGP::StandardPolicy.new, 1587301934)

    writer.sign(sigs, 0)
    writer.literal
    writer.write_all("Hello world!")
    writer.finalize
    buffer.rewind
    assert buffer.read
  end

  def test_sign_detached
    buffer = StringIO.new
    sink = OpenPGP::IOWriter.new_from_callback(buffer)
    writer = OpenPGP::WriterStack.new_message(sink)
    cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')
    sigs = get_signers_from_cert(cert, OpenPGP::StandardPolicy.new, 1587301934)

    writer.sign_detached(sigs, 0)
    writer.write_all("Hello world!")
    writer.finalize
    buffer.rewind
    assert buffer.read
  end
end
