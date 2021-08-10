require "ffi"
require "objspace"

require_relative '../stdio'

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :signature

  attach_function :pgp_signature_debug, [:signature], :strptr
  attach_function :pgp_signature_free, [:signature], :void

  class Signature < Packet
    def initialize(signature)
      @ref = signature
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_signature_free(@ref)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_signature_debug(@ref)
      Stdio.free(ptr)
      str
    end
  end
end
