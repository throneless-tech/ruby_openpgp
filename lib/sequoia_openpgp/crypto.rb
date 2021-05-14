require "ffi"
require "objspace"

require_relative "./error"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :signer
  typedef :pointer, :key_pair
  typedef :pointer, :session_key

  attach_function :pgp_key_pair_as_signer, [:key_pair], :signer
  attach_function :pgp_key_pair_new, [:error, :pointer, :pointer], :key_pair
  attach_function :pgp_key_pair_free, [:key_pair], :void
  attach_function :pgp_session_key_from_bytes, [:pointer, :size_t], :session_key
  attach_function :pgp_session_key_free, [:session_key], :void
  attach_function :pgp_signer_free, [:signer], :void

  class SessionKey
    attr_reader :ref

    def initialize(sk)
      @ref = sk
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      buf = FFI::MemoryPointer.new(:uint8_t, bytes.bytesize)
      buf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_session_key_from_bytes(buf, bytes.bytesize)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def self.new_from_bytes(bytes)
      session_key = allocate
      session_key.send(:initialize_from_bytes, bytes)
      session_key
    end

    def release
      OpenPGP.pgp_session_key_free(@ref)
    end
  end

  class Signer
    attr_reader :ref

    def initialize(signer)
      @ref = signer
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_signer_free(@ref)
    end
  end

  class KeyPair
    def initialize(keypair)
      @ref = keypair
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_raw(pk, sk)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_key_pair_new(error, pk.ref, sk.ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_key_pair_free(@ref)
    end

    def as_signer
      Signer.new(OpenPGP.pgp_key_pair_as_signer(@ref))
    end
  end
end
