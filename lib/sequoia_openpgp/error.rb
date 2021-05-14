require "ffi"
require "objspace"

require_relative "./stdio"
require_relative "./types_generator"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :error
  attach_function :pgp_error_free, [:error], :void
  attach_function :pgp_error_status, [:error], :int
  attach_function :pgp_error_to_string, [:error], :strptr
  attach_function :pgp_status_to_string, [:int], :string

  class Status
    def initialize(val)
      @status = val
    end

    def to_s
      OpenPGP.pgp_status_to_string(@status)
    end
  end

  class Error < StandardError
    def initialize(error)
      @ref = error
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
      super(OpenPGP.pgp_error_to_string(@ref))
    end

    def self.new(error)
      if error.null?
        return MalformedValueError.new()
      end
      case OpenPGP.pgp_error_status(error)
      when PGP_STATUS_SUCCESS
        Succes.new(error)
      when PGP_STATUS_UNKNOWN_ERROR
        UnknownError.new(error)
      when PGP_STATUS_NETWORK_POLICY_VIOLATION
        NetworkPolicyViolation.new(error)
      when PGP_STATUS_IO_ERROR
        IOError.new(error)
      when PGP_STATUS_INVALID_ARGUMENT
        InvalidArgument.new(error)
      when PGP_STATUS_INVALID_OPERATION
        InvalidOperation.new(error)
      when PGP_STATUS_MALFORMED_PACKET
        MalformedPacket.new(error)
      when PGP_STATUS_UNSUPPORTED_PACKET_TYPE
        UnsupportedPacketType.new(error)
      when PGP_STATUS_UNSUPPORTED_HASH_ALGORITHM
        UnsupportedHashAlgorithm.new(error)
      when PGP_STATUS_UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        UnsupportedPublicKeyAlgorithm.new(error)
      when PGP_STATUS_UNSUPPORTED_ELLIPTIC_CURVE
        UnsupportedEllipticCurve.new(error)
      when PGP_STATUS_UNSUPPORTED_SYMMETRIC_ALGORITHM
        UnsupportedSymmetricAlgorithm.new(error)
      when PGP_STATUS_UNSUPPORTED_AEAD_ALGORITHM
        UnsupportedAEADAlgorithm.new(error)
      when PGP_STATUS_UNSUPPORTED_COMPRESSION_ALGORITHM
        UnsupportedCompressionAlgorithm.new(error)
      when PGP_STATUS_UNSUPPORTED_SIGNATURE_TYPE
        UnsupportedSignatureType.new(error)
      when PGP_STATUS_INVALID_PASSWORD
        InvalidPassword.new(error)
      when PGP_STATUS_INVALID_SESSION_KEY
        InvalidSessionKey.new(error)
      when PGP_STATUS_MISSING_SESSION_KEY
        MissingSessionKey.new(error)
      when PGP_STATUS_MALFORMED_CERT
        MalformedCert.new(error)
      when PGP_STATUS_MALFORMED_MPI
        MalformedMPI.new(error)
      when PGP_STATUS_BAD_SIGNATURE
        BadSignature.new(error)
      when PGP_STATUS_MANIPULATED_MESSAGE
        ManipulatedMessage.new(error)
      when PGP_STATUS_MALFORMED_MESSAGE
        MalformedMessage.new(error)
      when PGP_STATUS_INDEX_OUT_OF_RANGE
        IndexOutOfRange.new(error)
      when PGP_STATUS_UNSUPPORTED_CERT
        UnsupportedCert.new(error)
      when PGP_STATUS_EXPIRED
        Expired.new(error)
      when PGP_STATUS_NOT_YET_LIVE
        NotYetLive.new(error)
      else
        MalformedValueError.new()
      end
    end

    def release
      OpenPGP.pgp_error_free(@ref)
    end

    def status
      Status.new(OpenPGP.pgp_error_status(@ref))
    end

    def to_s
      str, ptr = OpenPGP.pgp_error_to_string(@ref)
      Stdio.free(ptr)
      str
    end
  end

  class SQError < Error
    def self.new(object)
      error = allocate
      error.send(:initialize, object)
      error
    end
  end

  class Success < SQError
  end

  class UnknownError < SQError
  end

  class NetworkPolicyViolation < SQError
  end

  class IOError < SQError
  end

  class InvalidArgument < SQError
  end

  class InvalidOperation < SQError
  end

  class MalformedPacket < SQError
  end

  class UnsupportedPacketType < SQError
  end

  class UnsupportedHashAlgorithm < SQError
  end

  class UnsupportedPublicKeyAlgorithm < SQError
  end

  class UnsupportedEllipticCurve < SQError
  end

  class UnsupportedSymmetricAlgorithm < SQError
  end

  class UnsupportedAEADAlgorithm < SQError
  end

  class UnsupportedCompressionAlgorithm < SQError
  end

  class UnsupportedSignatureType < SQError
  end

  class InvalidPassword < SQError
  end

  class InvalidSessionKey < SQError
  end

  class MissingSessionKey < SQError
  end

  class MalformedCert < SQError
  end

  class MalformedMPI < SQError
  end

  class BadSignature < SQError
  end

  class ManipulatedMessage < SQError
  end

  class MalformedMessage < SQError
  end

  class IndexOutOfRange < SQError
  end

  class UnsupportedCert < SQError
  end

  class Expired < SQError
  end

  class NotYetLive < SQError
  end

  class MalformedValueError < StandardError
    def initialize(msg = "Malformed Value")
      super
    end
  end
end
