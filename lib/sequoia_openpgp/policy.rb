require "ffi"
require "objspace"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :policy

  attach_function :pgp_standard_policy, [], :policy
  attach_function :pgp_standard_policy_free, [:policy], :void

  class StandardPolicy
    attr_reader :ref

    def initialize
      @ref = OpenPGP.pgp_standard_policy
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_standard_policy_free(@ref)
    end
  end
end
