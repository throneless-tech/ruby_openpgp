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

    def decrypt_for(ciphertext:, recipient:, password: nil, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_bytes(ciphertext, PGP_ARMOR_KIND_MESSAGE)
      do_decrypt(source, recipient, password, outfile)
    end

    def decrypt_file_for(infile:, recipient:, password: nil, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_file(infile, PGP_ARMOR_KIND_FILE)
      do_decrypt(source, recipient, password, outfile)
    end

    def sign_with(plaintext:, sender:, password: nil, outfile: nil)
      do_sign(plaintext, sender, password, outfile)
    end

    def sign_file_with(infile:, sender:, password: nil, outfile: nil)
      plaintext = File.read(infile)
      do_sign(plaintext, sender, password, outfile)
    end

    def verify_from(ciphertext:, sender:, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_bytes(ciphertext, PGP_ARMOR_KIND_MESSAGE)
      do_verify(source, sender, outfile)
    end

    def verify_file_from(infile:, sender:, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_file(infile, PGP_ARMOR_KIND_FILE)
      do_verify(source, sender, outfile)
    end

    def verify_detached_from(plaintext:, signature:, sender:, outfile: nil)
      source = OpenPGP::ArmorReader.new_from_bytes(signature, PGP_ARMOR_KIND_MESSAGE)
      do_verify_detached(plaintext, source, sender, outfile)
    end

    def verify_detached_file_from(infile:, sigfile:, sender:, outfile: nil)
      plaintext = File.read(infile)
      source = OpenPGP::ArmorReader.new_from_file(sigfile, PGP_ARMOR_KIND_FILE)
      do_verify_detached(plaintext, source, sender, outfile)
    end

    def fingerprints_of(keys:)
      Array(keys).map do |key|
        OpenPGP::Cert.new_from_bytes(key).fingerprint.to_s
      end.flatten
    end

    def public_key_algos_of(keys:)
      Array(keys).map do |key|
        OpenPGP::Cert.new_from_bytes(key).public_key_algo
      end.flatten
    end

    def emails_of(keys:)
      Array(keys).map do |key|
        cert = OpenPGP::Cert.new_from_bytes(key)
        cert.user_ids(OpenPGP::StandardPolicy.new, Time.now.to_i)
            .map(&:user_id)
            .map(&:email_normalized)
      end.flatten
    end

    private

    def check_message(message)
      return PGP_STATUS_SUCCESS
      message_layers = message.layers.to_a

      # check that length is 2
      raise "unexpected length of message structure" unless message_layers.length == 2

      # check that it is one compression layer and one signature group
      variants = message_layers.map(&:variant)

      raise "unexpected ordering of message layers" unless variants == [PGP_MESSAGE_LAYER_COMPRESSION,
                                                                        PGP_MESSAGE_LAYER_SIGNATURE_GROUP]

      # get the verification results of the signature group and check that
      # it is a good signature
      groups = message_layers[1].signature_group.to_a
      raise "unexpected number of signatures" unless groups.length == 1

      good, = groups[0].good_checksum?
      raise "uncorrect checksum" unless good

      PGP_STATUS_SUCCESS
    end

    def load_session_keys(pkesks, _skesks)
      pkesks.each do |pkesk|
        @cert.key_amalgamations(@policy, @time).secret_keys.each do |ka|
          key = if @password && !ka.key.unencrypted_secret?
                  ka.key.decrypt_secret(@password)
                else
                  ka.key
                end
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

    def load_encryption_keys(keys)
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

    def load_signing_keys(keys)
      Array(keys).map do |key|
        cert = OpenPGP::Cert.new_from_bytes(key)
        cert.key_amalgamations(OpenPGP::StandardPolicy.new, Time.now.to_i)
            .secret_keys
            .for_signing
            .map do |ka|
              key = if @password && !ka.key.unencrypted_secret?
                      ka.key.decrypt_secret(@password)
                    else
                      ka.key
                    end
              key.clone.into_key_pair.as_signer
            end
      end.flatten
    end

    def write_armored(buffer, kind, outfile = nil)
      if outfile
        kind = PGP_ARMOR_KIND_FILE
        armored = OpenPGP::IOWriter.new_from_file(outfile)
      else
        armorbuff = StringIO.new
        armored = OpenPGP::IOWriter.new_from_callback(armorbuff)
      end

      unarmored = OpenPGP::IOReader.new_from_callback(buffer)
      armorer = OpenPGP::ArmorWriter.new(armored, kind, [])
      unarmored.copy(armorer, buffer.length)
      armorer.finalize
      return unless armorbuff

      armorbuff.rewind
      armorbuff.read
    end

    def do_encrypt(plaintext, recipients, outfile = nil)
      raise ArgumentError, "Plaintext must be a string!" unless plaintext.is_a?(String)

      keys = load_encryption_keys(recipients)

      buffer = StringIO.new
      sink = OpenPGP::IOWriter.new_from_callback(buffer)
      writer = OpenPGP::WriterStack.new_message(sink)
      passwords = %w[p f]

      writer.encrypt(passwords, keys, 0)
      writer.literal
      writer.write_all(plaintext)
      writer.finalize

      buffer.rewind
      write_armored(buffer, PGP_ARMOR_KIND_MESSAGE, outfile)
    end

    def do_decrypt(source, recipient, password, outfile)
      @cert = OpenPGP::Cert.new_from_bytes(recipient)
      @time = Time.now.to_i
      @policy = OpenPGP::StandardPolicy.new
      @password = password

      reader = OpenPGP::Reader.new(source, method(:load_public_keys), method(:check_message), @time, @policy)
      reader = reader.decrypt(method(:load_session_keys), nil)
      if outfile
        File.write(outfile, reader.read)
      else
        reader.read
      end
    end

    def do_sign(plaintext, sender, password, outfile)
      @password = password
      raise ArgumentError, "Plaintext must be a string!" unless plaintext.is_a?(String)

      keys = load_signing_keys(sender)

      buffer = StringIO.new
      sink = OpenPGP::IOWriter.new_from_callback(buffer)
      writer = OpenPGP::WriterStack.new_message(sink)

      writer.sign(keys, 0)
      writer.literal
      writer.write_all(plaintext)
      writer.finalize

      buffer.rewind
      write_armored(buffer, PGP_ARMOR_KIND_SIGNATURE, outfile)
    end

    def do_verify(source, sender, outfile)
      @cert = OpenPGP::Cert.new_from_bytes(sender)
      @time = Time.now.to_i
      @policy = OpenPGP::StandardPolicy.new

      reader = OpenPGP::Reader.new(source, method(:load_public_keys), method(:check_message), @time, @policy)
      reader = reader.verify
      if outfile
        File.write(outfile, reader.read)
      else
        reader.read
      end
    end

    def do_verify_detached(plaintext, source, sender, outfile = nil)
      @cert = OpenPGP::Cert.new_from_bytes(sender)
      @time = Time.now.to_i
      @policy = OpenPGP::StandardPolicy.new

      reader = OpenPGP::DetachedReader.new(source, method(:load_public_keys), method(:check_message), @time, @policy)
      reader = reader.verify(plaintext)
      if outfile
        File.write(outfile, reader.read)
      else
        reader.read
      end
    end
  end
end
