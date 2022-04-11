require "ffi"
require "objspace"

require_relative "../stdio"

module OpenPGP
  extend FFI::Library
  ffi_lib "libsequoia_openpgp_ffi"

  typedef :pointer, :user_id

  attach_function :pgp_user_id_debug, [:user_id], :strptr
  attach_function :pgp_user_id_free, [:user_id], :void
  attach_function :pgp_user_id_email, %i[error user_id string], :int
  attach_function :pgp_user_id_email_normalized, %i[error user_id string], :int

  class UserID < Packet
    def initialize(user_id)
      @ref = user_id
      ObjectSpace.define_finalizer(self, method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_user_id_free(@ref)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_user_id_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def email
      error = FFI::MemoryPointer.new(:pointer, 1)
      email = FFI::MemoryPointer.new(:pointer, 1)
      status = OpenPGP.pgp_user_id_email(error, @ref, email)

      raise Error, error.get_pointer(0) unless error.get_pointer(0).null?

      raise StandardError, "Unknown error occured serializing cert: " + status.to_s unless status == PGP_STATUS_SUCCESS

      email_ptr = email.read_pointer
      email_ptr.null? ? nil : email_ptr.read_string.force_encoding("UTF-8")
    end

    def email_normalized
      error = FFI::MemoryPointer.new(:pointer, 1)
      email = FFI::MemoryPointer.new(:pointer, 1)
      status = OpenPGP.pgp_user_id_email_normalized(error, @ref, email)

      raise Error, error.get_pointer(0) unless error.get_pointer(0).null?

      raise StandardError, "Unknown error occured serializing cert: " + status.to_s unless status == PGP_STATUS_SUCCESS

      email_ptr = email.read_pointer
      email_ptr.null? ? nil : email_ptr.read_string.force_encoding("UTF-8")
    end
  end
end
