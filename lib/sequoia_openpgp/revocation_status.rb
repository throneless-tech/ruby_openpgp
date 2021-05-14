require "ffi"
require "objspace"

require_relative './stdio'

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :revocation_status

  attach_function :pgp_revocation_status_debug, [:revocation_status], :strptr
  attach_function :pgp_revocation_status_free, [:revocation_status], :void

  class RevocationStatus
    def initialize(status)
      @status = status
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_revocation_status_free(@status)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_revocation_status_debug(@status)
      Stdio.free(ptr)
      str
    end
  end
end
