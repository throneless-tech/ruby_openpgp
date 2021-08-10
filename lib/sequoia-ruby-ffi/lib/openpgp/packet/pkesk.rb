require "ffi"
require "objspace"

require_relative "../error"
require_relative "../packet"
require_relative "../packet/key"
require_relative "../keyid"
require_relative "../types"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :pkesk

  attach_function :pgp_pkesk_decrypt, [:error, :pkesk, :key, :pointer, :pointer, :pointer], :int
  attach_function :pgp_pkesk_recipient, [:pkesk], :keyid

  class PKESK < Packet
    def initialize(pkesk)
      @ref = pkesk
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def decrypt(secret_key)
      default_length = 1024

      error = FFI::MemoryPointer.new(:pointer, 1)
      algo_ptr = FFI::MemoryPointer.new(:uint8, 1)
      session_key_ptr = FFI::MemoryPointer.new(:uint8, default_length)
      session_key_len_ptr = FFI::MemoryPointer.new(:size_t, 1)
      session_key_len_ptr.put(:size_t, 0, default_length)

      status = OpenPGP.pgp_pkesk_decrypt(error, @ref, secret_key.ref, algo_ptr, session_key_ptr, session_key_len_ptr)

      sk_length = session_key_len_ptr.get(:size_t, 0)
      if status != PGP_STATUS_SUCCESS || sk_length > default_length
        session_key_ptr = FFI::MemoryPointer.new(:uint8, sk_length)
        status = OpenPGP.pgp_pkesk_decrypt(error, @ref, secret_key.ref, algo_ptr, session_key_ptr, session_key_len_ptr)
        return nil if status != PGP_STATUS_SUCCESS
      end

      return SessionKey.new_from_bytes(session_key_ptr.get_bytes(0, sk_length)), algo_ptr.get_uint8(0)
    end

    def recipient
      KeyId.new(OpenPGP.pgp_pkesk_recipient(@ref))
    end
  end
end
