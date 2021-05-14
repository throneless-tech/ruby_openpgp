require "ffi"
require "objspace"

require_relative "../cert"
require_relative "../error"
require_relative "../io"
require_relative "../keyid"
require_relative "../crypto"
require_relative "../stdio"
require_relative "./message_structure"
require_relative "../packet/skesk"
require_relative "../packet/pkesk"
require_relative "../policy"
require_relative "../types_generator"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :writer_stack
  typedef :pointer, :helper_cookie
  typedef :pointer, :message_structure
  typedef :pointer, :packet_parser
  typedef :pointer, :detached_verifier

  # callbacks
  # do the real decryption
  DECRYPTOR_CB = callback :decryptor_do_decrypt_cb,
                          [:pointer, :uint8_t, :session_key],
                          :int
  # free some allocated memory
  callback :free_cb, [:pointer], :void
  # get the needed certificates
  callback :get_certs_cb,
           [:helper_cookie, :pointer, :size_t, :pointer, :pointer, :free_cb],
           :int
  # handle decryption
  callback :decrypt_cb,
           [:helper_cookie, :pointer, :size_t, :pointer, :size_t, :uint8_t,
            :decryptor_do_decrypt_cb, :pointer, :pointer],
           :int
  # verify message structure and signatures
  callback :check_cb, [:helper_cookie, :message_structure], :int
  # inspect the packets (optional)
  callback :inspect_cb, [:helper_cookie, :packet_parser], :int

  # functions
  attach_function :pgp_decryptor_new,
                  [:error, :policy, :reader, :get_certs_cb, :decrypt_cb,
                   :check_cb, :inspect_cb, :helper_cookie, :time_t],
                  :reader
  attach_function :pgp_verifier_new,
                  [:error, :policy, :reader, :get_certs_cb, :check_cb,
                   :inspect_cb, :helper_cookie, :time_t],
                  :reader
  attach_function :pgp_detached_verifier_new,
                  [:error, :policy, :reader, :get_certs_cb, :check_cb,
                   :inspect_cb, :helper_cookie, :time_t],
                  :detached_verifier
  attach_function :pgp_detached_verifier_verify,
                  [:error, :detached_verifier, :reader],
                  :int
  attach_function :pgp_detached_verifier_free, [:detached_verifier], :void

  # this module keeps all the callback wrappers, so they can be used
  # in the reader and in the detached_verifier
  module Callbacks
    def get_certs_cb(get_certs)
      FFI::Function.new(:int,
                        [:pointer,
                         :pointer,
                         :size_t,
                         :pointer,
                         :pointer,
                         :pointer]) do |_cookie, keyids, keyid_len, certs_ptr,
                                        cert_len_ptr, free_cb|

        # construct iterable of keyids
        keyid_ary = transform_keyids_c_to_ruby(keyids, keyid_len)

        # call get_certs(keyids)
        certificates = get_certs.call(keyid_ary)

        return PGP_STATUS_UNKNOWN_ERROR unless certificates.any?

        # store certificates a block allocated with malloc
        certs = transform_certs_ruby_to_c(certificates)
        certs_ptr.put_pointer(0, certs)
        cert_len_ptr.put_int(0, certificates.size)
        free_cb.put_pointer(0, Stdio::Free.address)

        # return status success, when there is no error
        PGP_STATUS_SUCCESS
      rescue SQError => e
        e.status
      end
    end

    def transform_keyids_c_to_ruby(keyids, keyid_len)
      keyids.read_array_of_pointer(keyid_len).map do |elem|
        KeyId.new(elem)
      end
    end

    def transform_certs_ruby_to_c(certificates)
      certs = Stdio.malloc(FFI::Pointer.size * certificates.size)
      certificates.each_with_index do |cert, i|
        certs.put_pointer(i * FFI::Pointer.size, cert.clone.ref)
      end
      certs
    end

    def check_cb(check)
      FFI::Function.new(:int,
                        [:pointer,
                         :pointer]) do |_cookie, message_structure|
        # transform message_structure to ruby
        msg = MessageStructure.new(message_structure)

        # call the check function and return the return value when
        # where is no error
        check.call(msg)
      rescue SQError => e
        e.status
      end
    end

    def decrypt_cb(get_session_key)
      FFI::Function.new(:int,
                        [:pointer,
                         :pointer,
                         :size_t,
                         :pointer,
                         :size_t,
                         :uint8_t,
                         OpenPGP::DECRYPTOR_CB,
                         :pointer,
                         :pointer]) do |_cookie, pkesk, pkesk_len, skesk,
                                        skesk_len, _sym_algo_hint, decrypt_fn,
                                        decrypt_cookie, identity_out|
        # transform pkesk and skesk packets to ruby
        pkesks = pkesk.read_array_of_pointer(pkesk_len).map do |elem|
          PKESK.new(elem)
        end

        skesks = skesk.read_array_of_pointer(skesk_len).map do |elem|
          SKESK.new(elem)
        end

        # TODO: sym_algo_hint can be passed on to pkesk.decrypt
        # eventually, but it is not supported in the c api until now

        # call decrypt to get the right session_key
        sk, algo, fingerprint = get_session_key.call(pkesks, skesks)

        # call decrypt_fn with the session_key
        ret = decrypt_fn.call(decrypt_cookie, algo, sk.ref)

        if fingerprint
          identity_out.put_pointer(0, fingerprint.clone.ref)
        end

        # transform bool in status
        if ret
          PGP_STATUS_SUCCESS
        else
          PGP_STATUS_UNKNOWN_ERROR
        end
      end
    end
  end

  class Reader
    include Callbacks

    def initialize(source, get_certs, check, time, policy)
      @source = source
      @get_certs = get_certs
      @check = check
      @time = time
      @policy = policy
    end

    def verify
      error = FFI::MemoryPointer.new(:pointer, 1)
      # FFI::Pointer::NULL is a placeholder for the callback-cookie
      plaintext = OpenPGP.pgp_verifier_new(error,
                                           @policy.ref,
                                           @source.ref,
                                           get_certs_cb(@get_certs),
                                           check_cb(@check),
                                           FFI::Pointer::NULL,
                                           FFI::Pointer::NULL,
                                           @time)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if plaintext.null?
        raise StandardError.new("Unknown Error occured creating verifier")
      end
      IOReader.new(plaintext)
    end

    def decrypt(get_session_key, inspect)
      error = FFI::MemoryPointer.new(:pointer, 1)
      # FFI::Pointer::NULL is a placeholder for the callback-cookie
      plaintext = OpenPGP.pgp_decryptor_new(error,
                                            @policy.ref,
                                            @source.ref,
                                            get_certs_cb(@get_certs),
                                            decrypt_cb(get_session_key),
                                            check_cb(@check),
                                            FFI::Pointer::NULL, #inspect,
                                            FFI::Pointer::NULL,
                                            @time)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if plaintext.null?
        raise StandardError.new("Unknown Error occured creating decryptor")
      end
      IOReader.new(plaintext)
    end
  end

  class DetachedReader
    include Callbacks

    def initialize(signature, get_certs, check, time, policy)
      error = FFI::MemoryPointer.new(:pointer, 1)
      # FFI::Pointer::NULL is a placeholder for the callback-cookie
      @ref = OpenPGP.pgp_detached_verifier_new(error,
                                               policy.ref,
                                               signature.ref,
                                               get_certs_cb(get_certs),
                                               check_cb(check),
                                               FFI::Pointer::NULL,
                                               FFI::Pointer::NULL,
                                               time)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown Error occured creating detached verifier")
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def verify(reader)
      error = FFI::MemoryPointer.new(:pointer, 1)
      validity = OpenPGP.pgp_detached_verifier_verify(error, @ref, reader.ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      Status.new(validity)
    end

    def release
      OpenPGP.pgp_detached_verifier_free(@ref)
    end
  end
end
