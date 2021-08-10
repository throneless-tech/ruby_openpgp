require "ffi"
require "objspace"

require_relative "../keyid"
require_relative "../fingerprint"
require_relative "../stdio"
require_relative "../packet"
require_relative "../crypto"
require_relative "../io"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :key
  attach_function :pgp_key_clone, [:key], :key
  attach_function :pgp_key_creation_time, [:key], :time_t
  attach_function :pgp_key_debug, [:key], :strptr
  attach_function :pgp_key_equal, [:key, :key], :bool
  attach_function :pgp_key_fingerprint, [:key], :fingerprint
  attach_function :pgp_key_free, [:key], :void
  attach_function :pgp_key_from_bytes, [:pointer, :pointer, :size_t], :key
  attach_function :pgp_key_from_file, [:pointer, :pointer], :key
  attach_function :pgp_key_from_reader, [:pointer, :reader], :key
  attach_function :pgp_key_into_key_pair, [:pointer, :key], :key_pair
  attach_function :pgp_key_keyid, [:key], :keyid
  attach_function :pgp_key_public_key_algo, [:key], :int
  attach_function :pgp_key_public_key_bits, [:key], :int

  class Key < Packet
    attr_reader :ref

    def initialize(key)
      @ref = key
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      error = FFI::MemoryPointer.new(:pointer, 1)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_key_from_bytes(error, memBuf, bytes.bytesize)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating key from bytes")
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_file(filename)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_key_from_file(error, filename)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating key from file " + filename)
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_reader(reader)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_key_from_reader(error, reader.ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating key from reader")
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_key_free(@ref)
    end

    def self.new_from_bytes(bytes)
      key = allocate
      key.send(:initialize_from_bytes, bytes)
      key
    end

    def self.new_from_file(filename)
      key = allocate
      key.send(:initialize_from_file, filename)
      key
    end

    def clone
      Key.new(OpenPGP.pgp_key_clone(@ref))
    end

    def creation_time
      OpenPGP.pgp_key_creation_time(@ref)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_key_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def ==(other)
      OpenPGP.pgp_key_equal(@ref, other.ref)
    end

    def eql?(other)
      OpenPGP.pgp_key_equal(@ref, other.ref)
    end

    def fingerprint
      Fingerprint.new(OpenPGP.pgp_key_fingerprint(@ref))
    end

    def into_key_pair
      error = FFI::MemoryPointer.new(:pointer, 1)
      keypair = OpenPGP.pgp_key_into_key_pair(error, @ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if keypair.null?
        raise StandardError.new("Unknown error occured creating key pair from key")
      end
      KeyPair.new(keypair)
    end

    def keyid
      KeyId.new(OpenPGP.pgp_key_keyid(@ref))
    end

    def public_key_algo
      OpenPGP.pgp_key_public_key_algo(@ref)
    end

    def public_key_bits
      OpenPGP.pgp_key_public_key_bits(@ref)
    end
  end
end
