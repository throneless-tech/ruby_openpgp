require_relative '../lib/openpgp'

def main
  source = OpenPGP::IOReader.new_from_file("test/unit/data/messages/signed-1-sha256-testy.gpg")

  # create lambda-function to get the right key. We know the right key in advance
  get_public_keys = ->(_keyids) do
    [OpenPGP::Cert.new_from_file("test/unit/data/keys/testy.pgp")]
  end

  # create lamda-function to verify the message
  check = ->(message_structure) do
    check_layers(message_structure)
  end

  reader = OpenPGP::Reader.new(source, get_public_keys, check, 1554542219, OpenPGP::StandardPolicy.new)
  reader = reader.verify

  content = reader.read(40)
  raise "unexpected content" unless content == "A Cypherpunk's Manifesto\nby Eric Hughes\n"
  puts content
end

def check_layers(message_structure)
  message_layers = message_structure.layers.to_a

  # check that length is 2
  raise "unexpected length of message structure" unless message_layers.length == 2

  # check that it is one compression layer and one signature group
  variants = message_layers.map do |layer|
    layer.variant
  end
  raise "unexpected ordering of message layers" unless variants == [PGP_MESSAGE_LAYER_COMPRESSION, PGP_MESSAGE_LAYER_SIGNATURE_GROUP]

  # get the verification results of the signature group and check that
  # it is a good signature
  groups = message_layers[1].signature_group.to_a
  raise "unexpected number of signatures" unless groups.length == 1
  good, _ = groups[0].good_checksum?
  raise "uncorrect checksum" unless good

  PGP_STATUS_SUCCESS
end

if __FILE__ == $0
  main
end
