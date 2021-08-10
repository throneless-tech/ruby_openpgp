require "ffi"
require "objspace"

require_relative "./stdio"
require_relative "./keyid"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :fingerprint

  attach_function :pgp_fingerprint_as_bytes, [:fingerprint, :pointer], :pointer
  attach_function :pgp_fingerprint_clone, [:fingerprint], :fingerprint
  attach_function :pgp_fingerprint_debug, [:fingerprint], :strptr
  attach_function :pgp_fingerprint_equal, [:fingerprint, :fingerprint], :bool
  attach_function :pgp_fingerprint_free, [:fingerprint], :void
  attach_function :pgp_fingerprint_from_bytes, [:pointer, :size_t], :fingerprint
  attach_function :pgp_fingerprint_from_hex, [:string], :fingerprint
  attach_function :pgp_fingerprint_hash, [:fingerprint], :uint64
  attach_function :pgp_fingerprint_to_hex, [:fingerprint], :strptr
  attach_function :pgp_fingerprint_to_keyid, [:fingerprint], :keyid
  attach_function :pgp_fingerprint_to_string, [:fingerprint], :strptr

  class Fingerprint
    attr_reader :ref

    def initialize(fingerprint)
      @ref = fingerprint
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_hex(hex)
      @ref = OpenPGP.pgp_fingerprint_from_hex(hex)
      if @ref.null?
        raise StandardError.new("Unknown error occured creating fingerprint from hex: " + hex)
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_fingerprint_from_bytes(memBuf, bytes.bytesize)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_fingerprint_free(@ref)
    end

    def self.new_from_hex(hex)
      fingerprint = allocate
      fingerprint.send(:initialize_from_hex, hex)
      fingerprint
    end

    def self.new_from_bytes(bytes)
      fingerprint = allocate
      fingerprint.send(:initialize_from_bytes, bytes)
      fingerprint
    end

    def ==(other)
      OpenPGP.pgp_fingerprint_equal(@ref, other.ref)
    end

    def eql?(other)
      OpenPGP.pgp_fingerprint_equal(@ref, other.ref)
    end

    def hash
      OpenPGP.pgp_fingerprint_hash(@ref)
    end

    def clone
      Fingerprint.new(OpenPGP.pgp_fingerprint_clone(@ref))
    end

    def as_bytes
      len = FFI::MemoryPointer.new(:size_t, 1, true)
      buf = OpenPGP.pgp_fingerprint_as_bytes(@ref, len)
      buf.read_string(len.get_int(0))
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_fingerprint_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def to_keyid
      KeyId.new(OpenPGP.pgp_fingerprint_to_keyid(@ref))
    end

    def to_hex
      str, ptr = OpenPGP.pgp_fingerprint_to_hex(@ref)
      Stdio.free(ptr)
      str
    end

    def to_s
      str, ptr = OpenPGP.pgp_fingerprint_to_string(@ref)
      Stdio.free(ptr)
      str
    end
  end
end
