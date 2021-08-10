require_relative '../lib/openpgp'

def main
  source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/a-cypherpunks-manifesto.txt")
  signature = OpenPGP::IOReader.new_from_file("test/unit/data/messages/a-cypherpunks-manifesto.txt.ed25519.sig")

  # create lambda-function to get the right key. We know the right key in advance
  get_public_keys = ->(_keyids) do
    [OpenPGP::Cert.new_from_file("test/unit/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")]
  end

  # create lamda-function to verify the message
  check = ->(message_structure) do
    check_layers(message_structure)
  end

  reader = OpenPGP::DetachedReader.new(signature, get_public_keys, check, 1554542219, OpenPGP::StandardPolicy.new)
  status = reader.verify(source)

  puts status.to_s
end

def check_layers(message_structure)
  message_layers = message_structure.layers.to_a

  # check that length is 1
  raise "unexpected length of message structure" unless message_layers.length == 1

  # check that it is one compression layer and one signature group
  groups = message_layers[0].signature_group.to_a
  raise "unexpected ordering of message layers" unless groups.any?

  # get the verification results of the signature group and check that
  # it is a good signature
  raise "unexpected number of signatures" unless groups.length == 1
  good, _ = groups[0].good_checksum?
  raise "uncorrect checksum" unless good

  PGP_STATUS_SUCCESS
end

if __FILE__ == $0
  main
end
