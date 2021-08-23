# require_relative "../sequoia-ruby-ffi"
require "sequoia-ruby-ffi"

module Sequoia
  class << self
    def encrypt_for(plaintext:, recipients:, outfile: nil)
      do_encrypt(plaintext, recipients, outfile)
    end

    def encrypt_file_for(infile:, recipients:, outfile: nil)
      # Seems like the upstream bindings only support writing bytes right now
      plaintext = File.read(infile)
      do_encrypt(plaintext, recipients, outfile)
    end

    def decrypt_for(ciphertext:, recipient:, outfile: nil)
      buffer = StringIO.new(ciphertext)
      source = OpenPGP::ArmorReader.new_from_bytes(buffer, 5)
      do_decrypt(source, recipient, outfile)
    end

    def decrypt_file_for(infile:, recipient:, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_file(infile, 5)
      do_decrypt(source, recipient, outfile)
    end

    private

    def check_message(_message)
      # This doesn't seem to be working correctly right now, so commented out
      #
      # message_layers = message.layers.to_a

      ## check that length is 2
      # raise "unexpected length of message structure" unless message_layers.length == 2

      ## check that it is one compression layer and one signature group
      # variants = message_layers.map &.variant

      # raise "unexpected ordering of message layers" unless variants == [PGP_MESSAGE_LAYER_COMPRESSION, PGP_MESSAGE_LAYER_SIGNATURE_GROUP]

      ## get the verification results of the signature group and check that
      ## it is a good signature
      # groups = message_layers[1].signature_group.to_a
      # raise "unexpected number of signatures" unless groups.length == 1

      # good, = groups[0].good_checksum?
      # raise "uncorrect checksum" unless good

      PGP_STATUS_SUCCESS
    end

    def load_session_keys(pkesks, _skesks)
      pkesks.each do |pkesk|
        @cert.key_amalgamations(@policy, @time).secret_keys.each do |ka|
          key = ka.key
          if key.keyid == pkesk.recipient
            sk, algo = pkesk.decrypt(key)
            return sk, algo, key.fingerprint
          end
        end
      end
      raise "Not a valid recipient for this message!"
    end

    def load_public_keys(_keyids)
      [@cert]
    end

    def load_recipient_keys(keys)
      Array(keys).map do |key|
        cert = OpenPGP::Cert.new_from_bytes(key)
        cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
            .for_transport_encryption
            .for_storage_encryption
            .map do |ka|
              OpenPGP::Recipient.new_from_key(ka.key)
            end
      end.flatten
    end

    def do_encrypt(plaintext, recipients, outfile = nil)
      raise ArgumentError, "Plaintext must be a string!" unless plaintext.is_a?(String)

      keys = load_recipient_keys(recipients)

      buffer = StringIO.new
      sink = OpenPGP::IOWriter.new_from_callback(buffer)
      writer = OpenPGP::WriterStack.new_message(sink)
      passwords = %w[p f]

      writer.encrypt(passwords, keys, 9, 0)
      writer.literal
      writer.write_all(plaintext)
      writer.finalize

      if outfile
        kind = PGP_ARMOR_KIND_FILE
        armored = OpenPGP::IOWriter.new_from_file(outfile)
      else
        kind = PGP_ARMOR_KIND_MESSAGE
        armorbuff = StringIO.new
        armored = OpenPGP::IOWriter.new_from_callback(armorbuff)
      end

      buffer.rewind
      unarmored = OpenPGP::IOReader.new_from_callback(buffer)
      armorer = OpenPGP::ArmorWriter.new(armored, kind, [])
      unarmored.copy(armorer, buffer.string.length)
      armorer.finalize
      return unless armorbuff

      armorbuff.rewind
      armorbuff.read
    end

    def do_decrypt(source, recipient, outfile = nil)
      @cert = OpenPGP::Cert.new_from_bytes(recipient)
      @time = Time.now.to_i
      @policy = OpenPGP::StandardPolicy.new

      reader = OpenPGP::Reader.new(source, method(:load_public_keys), method(:check_message), @time, @policy)
      reader = reader.decrypt(method(:load_session_keys), nil)
      if outfile
        File.write(outfile, reader.read)
      else
        reader.read
      end
    end
  end
end
