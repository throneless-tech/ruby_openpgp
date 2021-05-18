require_relative "../sequoia_openpgp"

def main
  source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/encrypted-to-testy.gpg")

  cert = OpenPGP::Cert.new_from_file("test/unit/data/keys/testy-private.pgp")

  policy = OpenPGP::StandardPolicy.new
  time = 1554542219

  get_public_keys = ->(_keyids) do
    [cert]
  end

  check = ->(message_structure) do
    check_layers(message_structure)
  end

  get_session_key = ->(pkesks, _skesks) do
    pkesks.each do |pkesk|
      cert.key_amalgamations(policy, time).secret_keys.each do |ka|
        key = ka.key
        if key.keyid == pkesk.recipient
          sk, algo = pkesk.decrypt(key)
          return sk, algo, key.fingerprint
        end
      end
    end

    # no password set, else check the skesks now...
  end

  reader = OpenPGP::Reader.new(source, get_public_keys, check, time, policy)
  reader = reader.decrypt(get_session_key, nil)

  content = reader.read
  puts content
end

def check_layers(message_structure)
  message_layers = message_structure.layers.to_a

  # expect encryption and compression
  raise "unexpected number of message layers" unless message_layers.length == 2

  # check it is an encryption layer
  variants = message_layers.map do |layer|
    layer.variant
  end
  raise "unexpected message layers" unless variants == [PGP_MESSAGE_LAYER_ENCRYPTION, PGP_MESSAGE_LAYER_COMPRESSION]
end

if __FILE__ == $0
  main
end
