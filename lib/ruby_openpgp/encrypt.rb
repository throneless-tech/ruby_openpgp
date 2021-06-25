require_relative "../sequoia_openpgp"

def main(file, pubkey, privkey, message)
  if __FILE__ == $0
    sink = OpenPGP::IOWriter.new_from_file(file)
    writer = OpenPGP::WriterStack.new_message(sink)
    pub = OpenPGP::Cert.new_from_file(pubkey)
    # priv = OpenPGP::Cert.new_from_file(privkey)
    passwords = ['p', 'f']

    recipients = []
    pub.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
      .for_transport_encryption
      .for_storage_encryption
      .each do |ka|
      recipients << OpenPGP::Recipient.new_from_key(ka.key)
    end

    # sigs = []
    # priv.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
    #   .secret_keys
    #   .for_signing
    #   .each do |ka|
    #   sigs << ka.key.clone.into_key_pair.as_signer
    # end

    writer.encrypt(passwords, recipients, 0)
    #writer.sign(sigs, 0)
    writer.literal
    writer.write_all(message)
    writer.finalize
  end
end

main(ARGV[0], ARGV[1], ARGV[2], ARGV[3])
