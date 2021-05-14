require "ffi"
require "objspace"

require_relative "./error"
require_relative "./io"
require_relative "./types_generator"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  class ArmorHeader < FFI::Struct
    layout :key, :string,
           :value, :string
    def set_key(key)
      self.pointer.put_pointer(offset_of(:key), FFI::MemoryPointer.from_string(key))
    end

    def set_value(value)
      self.pointer.put_pointer(offset_of(:value), FFI::MemoryPointer.from_string(value))
    end
  end

  typedef :pointer, :reader
  typedef :pointer, :armor_headers
  attach_function :pgp_armor_reader_from_bytes, [:pointer, :size_t, :int], :reader
  attach_function :pgp_armor_reader_from_file, [:error, :string, :int], :reader
  attach_function :pgp_armor_reader_new, [:reader, :int], :reader
  attach_function :pgp_armor_writer_new, [:error, :writer, :int, :armor_headers, :size_t], :writer
  attach_function :pgp_armor_writer_finalize, [:error, :writer], :int

  class ArmorWriter < IOWriter
    def initialize(writer, mode, headers)
      header = FFI::MemoryPointer.new(ArmorHeader, headers.size)
      headers.each_with_index do |h, idx|
        tmp = ArmorHeader.new
        tmp.set_key(h[0])
        tmp.set_value(h[1])
        header[idx].put_bytes(0, tmp.pointer.get_bytes(0, ArmorHeader.size))
      end
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_armor_writer_new(error, writer.ref, mode, header, headers.size)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating armor writer")
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def finalize
      error = FFI::MemoryPointer.new(:pointer, 1)
      status = OpenPGP.pgp_armor_writer_finalize(error, @ref)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      unless status == PGP_STATUS_SUCCESS
        raise StandardError.new("Error finalizing writer: " + Status.new(status).to_s)
      end
    end
  end

  # undefine inherited class method
  class <<ArmorWriter
    undef_method :new_from_bytes
    undef_method :new_from_fd
    undef_method :new_from_file
    undef_method :new_from_callback
  end

  class ArmorReader < IOReader
    def initialize_from_bytes(bytes, mode)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_armor_reader_from_bytes(memBuf, bytes.bytesize, mode)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_file(filename, mode)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_armor_reader_from_file(error, filename, mode)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating armor reader from file")
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize(reader, mode)
      @ref = OpenPGP.pgp_armor_reader_new(reader.ref, mode)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def self.new_from_bytes(bytes, mode)
      reader = allocate
      reader.send(:initialize_from_bytes, bytes, mode)
      reader
    end

    def self.new_from_file(filename, mode)
      reader = allocate
      reader.send(:initialize_from_file, filename, mode)
      reader
    end
  end

  # undefine inherited class method
  class <<ArmorReader
    undef_method :new_from_fd
    undef_method :new_from_callback
  end
end
