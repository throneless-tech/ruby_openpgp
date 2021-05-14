require "ffi"
require "objspace"

require_relative "./stdio"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :keyid

  attach_function :pgp_keyid_clone, [:keyid], :keyid
  attach_function :pgp_keyid_debug, [:keyid], :strptr
  attach_function :pgp_keyid_equal, [:keyid, :keyid], :bool
  attach_function :pgp_keyid_free, [:keyid], :void
  attach_function :pgp_keyid_from_bytes, [:pointer], :keyid
  attach_function :pgp_keyid_from_hex, [:string], :keyid
  attach_function :pgp_keyid_hash, [:keyid], :uint64
  attach_function :pgp_keyid_to_hex, [:keyid], :strptr
  attach_function :pgp_keyid_to_string, [:keyid], :strptr

  class KeyId
    attr_reader :ref

    def initialize(keyId)
      @ref = keyId
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_hex(hex)
      @ref = OpenPGP.pgp_keyid_from_hex(hex)
      if @ref.null?
        raise StandardError.new("Unknown error creating keyid from hex: " + hex)
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_keyid_from_bytes(memBuf)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_keyid_free(@ref)
    end

    def self.new_from_hex(hex)
      keyid = allocate
      keyid.send(:initialize_from_hex, hex)
      keyid
    end

    def self.new_from_bytes(bytes)
      keyid = allocate
      keyid.send(:initialize_from_bytes, bytes)
      keyid
    end

    def ==(other)
      OpenPGP.pgp_keyid_equal(@ref, other.ref)
    end

    def eql?(other)
      OpenPGP.pgp_keyid_equal(@ref, other.ref)
    end

    def hash
      OpenPGP.pgp_keyid_hash(@ref)
    end

    def clone
      KeyId.new(OpenPGP.pgp_keyid_clone(@ref))
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_keyid_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def to_hex
      str, ptr = OpenPGP.pgp_keyid_to_hex(@ref)
      Stdio.free(ptr)
      str
    end

    def to_s
      str, ptr = OpenPGP.pgp_keyid_to_string(@ref)
      Stdio.free(ptr)
      str
    end
  end
end
