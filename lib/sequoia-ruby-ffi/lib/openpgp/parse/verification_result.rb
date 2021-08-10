require "ffi"
require "objspace"

require_relative '../stdio'
require_relative '../packet/signature'
require_relative '../cert'
require_relative '../packet/key'
require_relative '../revocation_status'

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :verification_result_iter
  typedef :pointer, :verification_result

  attach_function :pgp_verification_result_good_checksum, [:verification_result, :signature, :cert, :key, :signature, :revocation_status], :bool
  attach_function :pgp_verification_result_free, [:verification_result], :void
  attach_function :pgp_verification_result_iter_free, [:verification_result_iter], :void
  attach_function :pgp_verification_result_iter_next, [:verification_result_iter], :verification_result

  class VerificationResultIter
    include Enumerable

    def initialize(iter)
      @ref = iter
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_verification_result_iter_free(@ref)
    end

    def each(&block)
      while result = next_result
        yield result
      end
    end

    def next_result
      result = OpenPGP.pgp_verification_result_iter_next(@ref)
      VerificationResult.new(result) unless result.null?
    end
  end

  class VerificationResult
    def initialize(result)
      @ref = result
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_verification_result_free(@ref)
    end

    def good_checksum?
      signature_ptr = FFI::MemoryPointer.new(:pointer, 1)
      cert_ptr = FFI::MemoryPointer.new(:pointer, 1)
      key_ptr = FFI::MemoryPointer.new(:pointer, 1)
      binding_ptr = FFI::MemoryPointer.new(:pointer, 1)
      revocation_ptr = FFI::MemoryPointer.new(:pointer, 1)

      ret = OpenPGP.pgp_verification_result_good_checksum(@ref, signature_ptr, cert_ptr, key_ptr, binding_ptr, revocation_ptr)

      return [
        ret,
        Signature.new(signature_ptr.get_pointer(0)),
        Cert.new(cert_ptr.get_pointer(0)),
        Key.new(key_ptr.get_pointer(0)),
        Signature.new(binding_ptr.get_pointer(0)),
        RevocationStatus.new(revocation_ptr.get_pointer(0))
      ]
    end
  end
end
