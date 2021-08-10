require_relative '../lib/openpgp'

if __FILE__ == $0
  sink = OpenPGP::IOWriter.new_from_file('hello_signature.txt')
  writer = OpenPGP::WriterStack.new_message(sink)
  cert = OpenPGP::Cert.new_from_file('test/unit/data/keys/transport-encryption-test-key')

  sigs = []
  cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
    .secret_keys
    .for_signing
    .each do |ka|
    sigs << ka.key.clone.into_key_pair.as_signer
  end

  writer.sign_detached(sigs, 0)
  writer.write_all('Hello world!')
  writer.finalize
end
