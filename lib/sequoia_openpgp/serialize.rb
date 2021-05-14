require "ffi"
require "objspace"

require_relative "./io"
require_relative "./error"
require_relative "./packet/key"
require_relative "./keyid"
require_relative "./cert"
require_relative "./types_generator"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :writer_stack
  typedef :pointer, :recipient

  attach_function :pgp_writer_stack_message, [:writer], :writer_stack
  attach_function :pgp_writer_stack_write, [:error, :writer_stack, :pointer, :size_t], :ssize_t
  attach_function :pgp_writer_stack_write_all, [:error, :writer_stack, :pointer, :size_t], :int
  attach_function :pgp_literal_writer_new, [:error, :writer_stack], :writer_stack
  attach_function :pgp_arbitrary_writer_new, [:error, :writer_stack, :uint8], :writer_stack
  attach_function :pgp_encryptor_new, [:error, :writer_stack, :pointer, :size_t, :pointer, :size_t, :uint8], :writer_stack
  attach_function :pgp_recipient_free, [:recipient], :void
  attach_function :pgp_recipient_new, [:keyid, :key], :recipient
  attach_function :pgp_signer_new, [:error, :writer_stack, :pointer, :size_t, :uint8], :writer_stack
  attach_function :pgp_signer_new_detached, [:error, :writer_stack, :pointer, :size_t, :uint8], :writer_stack
  attach_function :pgp_writer_stack_finalize, [:error, :writer_stack], :int
  attach_function :pgp_writer_stack_finalize_one, [:error, :writer_stack], :writer_stack

  class Recipient
    attr_reader :ref

    def initialize_from_key(key)
      @ref = OpenPGP.pgp_recipient_new(key.keyid.ref, key.ref)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def self.new_from_key(key)
      recipient = allocate
      recipient.send(:initialize_from_key, key)
      recipient
    end

    def release
      OpenPGP.pgp_recipient_free(@ref)
    end
  end

  class WriterStack
    attr_reader :ref
    def initialize_from_writer(writer)
      @ref = OpenPGP.pgp_writer_stack_message(writer.ref)
    end

    def self.new_message(writer)
      writer_stack = allocate
      writer_stack.send(:initialize_from_writer, writer)
      writer_stack
    end

    def write(bytes)
      error = FFI::MemoryPointer.new(:pointer, 1)
      mem_buf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      mem_buf.put_bytes(0, bytes)
      written = OpenPGP.pgp_writer_stack_write(error, @ref, mem_buf, bytes.bytesize)
      if written < 0
        raise Error.new(error.get_pointer(0))
      else
        written
      end
    end

    def write_all(bytes)
      error = FFI::MemoryPointer.new(:pointer, 1)
      mem_buf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      mem_buf.put_bytes(0, bytes)
      status = OpenPGP.pgp_writer_stack_write_all(error, @ref, mem_buf, bytes.bytesize)
      unless status == PGP_STATUS_SUCCESS
        raise Error.new(error.get_pointer(0))
      end
      Status.new(status)
    end

    def literal
      error = FFI::MemoryPointer.new(:pointer, 1)
      tmp = OpenPGP.pgp_literal_writer_new(error, @ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end

    def arbitrary(tag)
      error = FFI::MemoryPointer.new(:pointer, 1)
      tmp = OpenPGP.pgp_arbitrary_writer_new(error, @ref, tag.value)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end

    def encrypt(ps, recipients, cipher)
      error = FFI::MemoryPointer.new(:pointer, 1)
      if ps && ps.length > 0
        passwords = FFI::MemoryPointer.new(:pointer, ps.length)
        ps.each_with_index do |p, i|
          str_ptr = FFI::MemoryPointer.from_string(p)
          passwords[i].put_pointer(0, str_ptr)
        end
        passwords_len = ps.length
      else
        passwords = nil
        passwords_len = 0
      end

      if recipients&.any?
        recipients_ptr = FFI::MemoryPointer.new(:pointer, recipients.length)
        recipients.each_with_index do |r, i|
          recipients_ptr[i].put_pointer(0, r.ref)
        end
        recipients_len = recipients.length
      else
        recipients_ptr = nil
        recipients_len = 0
      end

      tmp = OpenPGP.pgp_encryptor_new(error, @ref, passwords, passwords_len, recipients_ptr, recipients_len, cipher)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end

    def sign(sigs, hash)
      error = FFI::MemoryPointer.new(:pointer, 1)

      if sigs && sigs.length > 0
        signers = FFI::MemoryPointer.new(:pointer, sigs.length)
        sigs.each_with_index do |signer, i|
          signers[i].put_pointer(0, signer.ref)
        end
        signers_len = sigs.length
      else
        raise StandardError.new("At least one signer is needed to sign a packet.")
      end
      tmp = OpenPGP.pgp_signer_new(error, @ref, signers, signers_len, hash)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end

    def sign_detached(sigs, hash)
      error = FFI::MemoryPointer.new(:pointer, 1)

      if sigs && sigs.length > 0
        signers = FFI::MemoryPointer.new(:pointer, sigs.length)
        sigs.each_with_index do |signer, i|
          signers[i].put_pointer(0, signer.ref)
        end
        signers_len = sigs.length
      else
        raise StandardError.new("At least one signer is needed to sign a packet.")
      end
      tmp = OpenPGP.pgp_signer_new_detached(error, @ref, signers, signers_len, hash)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end

    def finalize
      error = FFI::MemoryPointer.new(:pointer, 1)
      rc = OpenPGP.pgp_writer_stack_finalize(error, @ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      Status.new(rc)
    end

    def finalize_one
      error = FFI::MemoryPointer.new(:pointer, 1)
      tmp = OpenPGP.pgp_writer_stack_finalize_one(error, @ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      @ref = tmp
    end
  end
end
