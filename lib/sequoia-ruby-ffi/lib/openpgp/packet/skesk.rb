require "ffi"
require "objspace"

require_relative "../error"
require_relative "../packet"
require_relative "../packet/key"
require_relative "../types"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :skesk

  attach_function :pgp_skesk_decrypt, [:error, :skesk, :pointer, :size_t, :pointer, :pointer, :pointer], :int

  class SKESK < Packet
    def initialize(pkesk)
      @ref = pkesk
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def decrypt(password)
      error = FFI::MemoryPointer.new(:pointer, 1)
      algo_ptr = FFI::MemoryPointer.new(:uint8, 1)
      session_key_ptr = FFI::MemoryPointer.new(:uint8, 1024)
      session_key_len_ptr = FFI::MemoryPointer.new(:size_t, 1)
      password_buf = FFI::MemoryPointer.new(:char, password.bytesize)
      password_buf.put_bytes(0, password)
      status = OpenPGP.pgp_skesk_decrypt(error, @ref, password_buf, password.bytesize, algo_ptr, session_key_ptr, session_key_len_ptr)
      if status != PGP_STATUS_SUCCESS || session_key_len_ptr.get(:size_t, 0) > 1024
        session_key_ptr = FFI::MemoryPointer.new(:uint8, session_key_len_ptr.get(:size_t, 0))
      end
      status = OpenPGP.pgp_pkesk_decrypt(error, @ref, password_buf, password.bytesize, algo_ptr, session_key_ptr, session_key_len_ptr)
      return nil if status != PGP_STATUS_SUCCESS

      return SessionKey.new(session_key), algo_ptr.get_uint8(0)
    end
  end
end
