require "ffi"
require "objspace"

require_relative "./packet/user_id"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :valid_user_id_amalgamation

  attach_function :pgp_valid_user_id_amalgamation_free, [:valid_user_id_amalgamation], :void
  attach_function :pgp_valid_user_id_amalgamation_user_id, [:valid_user_id_amalgamation], :user_id

  class ValidUserIDAmalgamation
    def initialize(amalgamation)
      @ref = amalgamation
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_valid_user_id_amalgamation_free(@ref)
    end

    def user_id
      UserID.new(OpenPGP.pgp_valid_user_id_amalgamation_user_id(@ref))
    end
  end

end
