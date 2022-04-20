require "ffi"
require "objspace"
require "time"

require_relative "./error"
require_relative "./io"
require_relative "./fingerprint"
require_relative "./key_amalgamation"
require_relative "./amalgamation"
require_relative "./packet/key"
require_relative "./packet/user_id"
require_relative "./policy"
require_relative "./stdio"
require_relative "./types"

module OpenPGP
  extend FFI::Library
  ffi_lib "libsequoia_openpgp_ffi"

  typedef :pointer, :cert
  typedef :pointer, :valid_key_iter_wrapper

  typedef :pointer, :userid
  typedef :pointer, :valid_user_id_iter_wrapper

  attach_function :pgp_cert_from_bytes, %i[pointer pointer size_t], :cert
  attach_function :pgp_cert_debug, [:cert], :strptr
  attach_function :pgp_cert_from_file, %i[pointer string], :cert
  attach_function :pgp_cert_fingerprint, [:cert], :fingerprint
  attach_function :pgp_cert_free, [:cert], :void
  attach_function :pgp_cert_valid_key_iter, %i[cert policy time_t], :valid_key_iter_wrapper
  attach_function :pgp_cert_valid_key_iter_for_signing, [:valid_key_iter_wrapper], :void
  attach_function :pgp_cert_valid_key_iter_for_storage_encryption, [:valid_key_iter_wrapper], :void
  attach_function :pgp_cert_valid_key_iter_for_transport_encryption, [:valid_key_iter_wrapper], :void
  attach_function :pgp_cert_valid_key_iter_free, [:valid_key_iter_wrapper], :void
  attach_function :pgp_cert_valid_key_iter_next, %i[valid_key_iter_wrapper pointer pointer], :key
  attach_function :pgp_cert_valid_key_iter_secret, [:valid_key_iter_wrapper], :void
  attach_function :pgp_cert_serialize, %i[error cert writer], :int
  attach_function :pgp_cert_valid_user_id_iter, %i[cert policy time_t], :valid_user_id_iter_wrapper
  attach_function :pgp_cert_valid_user_id_iter_free, [:valid_user_id_iter_wrapper], :void
  attach_function :pgp_cert_valid_user_id_iter_next, %i[valid_user_id_iter_wrapper pointer pointer], :userid

  class CertValidKeyIter
    include Enumerable
    attr_reader :ref

    def initialize(key_iter)
      @ref = key_iter
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def initialize_from_cert(cert, policy, time)
      @ref = OpenPGP.pgp_cert_valid_key_iter(cert.ref, policy.ref, time)
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def self.new_from_cert(cert, policy, time)
      iter = allocate
      iter.send(:initialize_from_cert, cert, policy, time)
      iter
    end

    def release
      OpenPGP.pgp_cert_valid_key_iter_free(@ref)
    end

    def each
      while ka = next_key_amalgamation
        yield ka
      end
    end

    def next_key_amalgamation
      # TODO: add support for sigo and rso later!
      ka = OpenPGP.pgp_cert_valid_key_iter_next(@ref, nil, nil)
      ValidKeyAmalgamation.new(ka) unless ka.null?
    end

    def secret_keys
      OpenPGP.pgp_cert_valid_key_iter_secret(@ref)
      self
    end

    def for_signing
      OpenPGP.pgp_cert_valid_key_iter_for_signing(@ref)
      self
    end

    def for_storage_encryption
      OpenPGP.pgp_cert_valid_key_iter_for_storage_encryption(@ref)
      self
    end

    def for_transport_encryption
      OpenPGP.pgp_cert_valid_key_iter_for_transport_encryption(@ref)
      self
    end
  end

  class CertValidUserIdIter
    include Enumerable
    attr_reader :ref

    def initialize(key_iter)
      @ref = key_iter
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def initialize_from_cert(cert, policy, time)
      @ref = OpenPGP.pgp_cert_valid_user_id_iter(cert.ref, policy.ref, time)
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def self.new_from_cert(cert, policy, time)
      iter = allocate
      iter.send(:initialize_from_cert, cert, policy, time)
      iter
    end

    def release
      OpenPGP.pgp_cert_valid_user_id_iter_free(@ref)
    end

    def each
      while ka = next_user_id
        yield ka
      end
    end

    def next_user_id
      # TODO: add support for sigo and rso later!
      user_id = OpenPGP.pgp_cert_valid_user_id_iter_next(@ref, nil, nil)
      ValidUserIDAmalgamation.new(user_id) unless user_id.null?
    end
  end

  class Cert
    attr_reader :ref

    def initialize(cert)
      @ref = cert
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def initialize_from_file(filename)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_cert_from_file(error, filename)
      raise Error, error.get_pointer(0) unless error.get_pointer(0).null?
      raise StandardError, "Unknown error occured creating cert from file" if @ref.null?

      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      error = FFI::MemoryPointer.new(:pointer, 1)
      buf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      buf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_cert_from_bytes(error, buf, bytes.bytesize)
      raise Error, error.get_pointer(0) unless error.get_pointer(0).null?
      raise StandardError, "Unknown error occured creating cert from file" if @ref.null?

      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def self.new_from_file(filename)
      cert = allocate
      cert.send(:initialize_from_file, filename)
      cert
    end

    def self.new_from_bytes(bytes)
      cert = allocate
      cert.send(:initialize_from_bytes, bytes)
      cert
    end

    def release
      OpenPGP.pgp_cert_free(@ref)
    end

    def fingerprint
      Fingerprint.new(OpenPGP.pgp_cert_fingerprint(@ref))
    end

    # this is a convinience function to get an iterator for this
    # certificate.
    def key_amalgamations(policy, time)
      CertValidKeyIter.new_from_cert(self, policy, time)
    end

    def user_ids(policy, time)
      CertValidUserIdIter.new_from_cert(self, policy, time)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_cert_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def serialize(writer)
      error = FFI::MemoryPointer.new(:pointer, 1)
      status = OpenPGP.pgp_cert_serialize(error, @ref, writer.ref)

      raise Error, error.get_pointer(0) unless error.get_pointer(0).null?

      raise StandardError, "Unknown error occured serializing cert: " + status.to_s unless status == PGP_STATUS_SUCCESS
    end
  end
end
