require "ffi"
require "objspace"

require_relative "./packet/key"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :valid_key_amalgamation

  attach_function :pgp_valid_key_amalgamation_free, [:valid_key_amalgamation], :void
  attach_function :pgp_valid_key_amalgamation_key, [:valid_key_amalgamation], :key

  class ValidKeyAmalgamation
    def initialize(amalgamation)
      @ref = amalgamation
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_valid_key_amalgamation_free(@ref)
    end

    def key
      Key.new(OpenPGP.pgp_valid_key_amalgamation_key(@ref))
    end
  end

end
