require_relative "../sequoia_openpgp"

module RubyOpenPGP
  class Encrypt
    def initialize(public_key, private_key)
      @public_key = public_key
      @private_key = private_key
      @last_update = 0
    end

    def encrypt_for(file, message)
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

    def sign_detached_for(file, message)
      if __FILE__ == $0
        sink = OpenPGP::IOWriter.new_from_file(file)
        writer = OpenPGP::WriterStack.new_message(sink)
        cert = OpenPGP::Cert.new_from_file(@public_key)

        sigs = []
        cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
          .secret_keys
          .for_signing
          .each do |ka|
          sigs << ka.key.clone.into_key_pair.as_signer
        end

        writer.sign_detached(sigs, 0)
        writer.write_all(message)
        writer.finalize
      end
    end

    def sign_for(file_with_sig, message)
      if __FILE__ == $0
        sink = OpenPGP::IOWriter.new_from_file(file_with_sig)
        writer = OpenPGP::WriterStack.new_message(sink)
        cert = OpenPGP::Cert.new_from_file(@public_key)

        sigs = []
        cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
          .secret_keys
          .for_signing
          .each do |ka|
          sigs << ka.key.clone.into_key_pair.as_signer
        end

        writer.sign(sigs, 0)
        writer.literal
        writer.write_all(message)
        writer.finalize
      end
    end

    def stream_decrypt_file(file)
      def main
        source = OpenPGP::IOReader.new_from_file(file)

        cert = OpenPGP::Cert.new_from_file(@public_key)

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
    end

    def stream_verify_detached_signature(file, signature, public_keys)
      def main
        source = OpenPGP::IOReader.new_from_file(file)
        signature = OpenPGP::IOReader.new_from_file(signature)

        # create lambda-function to get the right key. We know the right key in advance
        get_public_keys = ->(_keyids) do
          [OpenPGP::Cert.new_from_file(public_keys)]
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
    end

    def stream_verify_signature(message, keys)
      def main
        source = OpenPGP::IOReader.new_from_file(message)

        # create lambda-function to get the right key. We know the right key in advance
        get_public_keys = ->(_keyids) do
          [OpenPGP::Cert.new_from_file(keys)]
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

    end
  end
end
