require_relative "../sequoia_openpgp"

def main(file, message)
  if __FILE__ == $0
    sink = OpenPGP::IOWriter.new_from_file(file)
    writer = OpenPGP::WriterStack.new_message(sink)
    cert = OpenPGP::Cert.new_from_file(@public_key)
    passwords = ['p', 'f']

    recipients = []
    cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
      .for_transport_encryption
      .for_storage_encryption
      .each do |ka|
      recipients << OpenPGP::Recipient.new_from_key(ka.key)
    end

    sigs = []
    cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
      .secret_keys
      .for_signing
      .each do |ka|
      sigs << ka.key.clone.into_key_pair.as_signer
    end

    writer.encrypt(passwords, recipients, 0)
    writer.sign(sigs, 0)
    writer.literal
    writer.write_all(message)
    writer.finalize
  end
end
