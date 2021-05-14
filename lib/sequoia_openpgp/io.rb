require "ffi"
require "objspace"
require "stringio"

require_relative "./error"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :reader
  typedef :pointer, :writer
  callback :readwrite_cb, [:pointer, :pointer, :size_t], :ssize_t
  attach_function :pgp_reader_copy, [:error, :reader, :writer, :size_t], :ssize_t
  attach_function :pgp_reader_discard, [:error, :reader], :ssize_t
  attach_function :pgp_reader_free, [:reader], :void
  attach_function :pgp_reader_from_bytes, [:pointer, :size_t], :reader
  attach_function :pgp_reader_from_callback, [:readwrite_cb, :pointer], :reader
  attach_function :pgp_reader_from_fd, [:int], :reader
  attach_function :pgp_reader_from_file, [:error, :string], :reader
  attach_function :pgp_reader_read, [:error, :reader, :pointer, :size_t], :ssize_t
  attach_function :pgp_writer_free, [:writer], :void
  attach_function :pgp_writer_from_bytes, [:pointer, :size_t], :writer
  attach_function :pgp_writer_from_callback, [:readwrite_cb, :pointer], :writer
  attach_function :pgp_writer_from_fd, [:int], :writer
  attach_function :pgp_writer_from_file, [:error, :string], :writer
  attach_function :pgp_writer_write, [:error, :writer, :pointer, :size_t], :ssize_t

  class IOReader
    attr_reader :ref

    def initialize(reader)
      @ref = reader
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      @ref = OpenPGP.pgp_reader_from_bytes(memBuf, bytes.bytesize)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_callback(object, callback)
      read_cb = FFI::Function.new(:ssize_t,
                                  [:pointer,
                                   :pointer,
                                   :size_t]) do |_cookie, buffer, length|
        str = object.read(length)
        buffer.write_string(str, str.length)
        str.length
      end

      cb = callback ? callback : read_cb
      @ref = OpenPGP.pgp_reader_from_callback(cb, nil)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_fd(fd)
      @ref = OpenPGP.pgp_reader_from_fd(fd)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_file(filename)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_reader_from_file(error, filename)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured creating reader from file: " + filename)
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def self.new_from_bytes(bytes)
      reader = allocate
      reader.send(:initialize_from_bytes, bytes)
      reader
    end

    def self.new_from_callback(object, callback=nil)
      reader = allocate
      reader.send(:initialize_from_callback, object, callback)
      reader
    end

    def self.new_from_fd(fd)
      reader = allocate
      reader.send(:initialize_from_fd, fd)
      reader
    end

    def self.new_from_file(filename)
      reader = allocate
      reader.send(:initialize_from_file, filename)
      reader
    end

    def release
      OpenPGP.pgp_reader_free(@ref)
    end

    def copy(writer, length)
      error = FFI::MemoryPointer.new(:pointer, 1)
      val = OpenPGP.pgp_reader_copy(error, @ref, writer.ref, length)
      if val < 0
        raise Error.new(error.get_pointer(0))
      else
        return val
      end
    end

    def discard
      error = FFI::MemoryPointer.new(:pointer, 1)
      val = OpenPGP.pgp_reader_discard(error, @ref)
      if val < 0
        raise Error.new(error.get_pointer(0))
      else
        return val
      end
    end

    # the behaviour and the output are analogous to IO#read
    def read(length = nil, outbuf = nil)
      if length == 0
        outbuf.replace("") if outbuf

        return ""
      end

      # read the whole data
      if length.nil?
        buf = StringIO.new
        l = 1024 # TODO: think of a plausible length here

        while
          val = read_helper(l, buf)
          break if val < l
        end

        buf.rewind
        content = buf.read
        outbuf.replace(content) if outbuf

        return content
      end

      if length > 0
        error = FFI::MemoryPointer.new(:pointer, 1)
        memBuf = FFI::MemoryPointer.new(:char, length)
        val = OpenPGP.pgp_reader_read(error, @ref, memBuf, length)

        if val < 0
          raise Error.new(error.get_pointer(0))
        elsif val == 0
          outbuf.replace("") if outbuf

          return nil
        else
          content = memBuf.get_bytes(0, val)
          outbuf.replace(content) if outbuf

          return content
        end
      end
    end

    private

    def read_helper(length, iowriter)
      error = FFI::MemoryPointer.new(:pointer, 1)
      memBuf = FFI::MemoryPointer.new(:char, length)
      val = OpenPGP.pgp_reader_read(error, @ref, memBuf, length)
      if val < 0
        raise Error.new(error.get_pointer(0))
      end

      iowriter.write(memBuf.get_bytes(0, val))
      val
    end
  end

  class IOWriter
    attr_reader :ref

    def initialize(writer)
      @ref = writer
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_bytes(bytes)
      @ref = OpenPGP.pgp_writer_from_bytes(bytes, bytes.size)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_callback(object, callback)
      write_cb = FFI::Function.new(:ssize_t,
                                   [:pointer,
                                    :pointer,
                                    :size_t]) do |_cookie, buffer, length|
        str = buffer.read_string(length)
        object.write(str)
      end

      cb = callback ? callback : write_cb
      @ref = OpenPGP.pgp_writer_from_callback(cb, nil)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_fd(fd)
      @ref = OpenPGP.pgp_writer_from_fd(fd)
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def initialize_from_file(filename)
      error = FFI::MemoryPointer.new(:pointer, 1)
      @ref = OpenPGP.pgp_writer_from_file(error, filename)
      if !error.get_pointer(0).null?
        raise Error.new(error.get_pointer(0))
      end
      if @ref.null?
        raise StandardError.new("Unknown error occured while creating writer from file: " + filename)
      end
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def self.new_from_bytes(bytes)
      writer = allocate
      writer.send(:initialize_from_bytes, bytes)
      writer
    end

    def self.new_from_callback(object, callback=nil)
      writer = allocate
      writer.send(:initialize_from_callback, object, callback)
      writer
    end

    def self.new_from_fd(fd)
      writer = allocate
      writer.send(:initialize_from_fd, fd)
      writer
    end

    def self.new_from_file(filename)
      writer = allocate
      writer.send(:initialize_from_file, filename)
      writer
    end

    def release
      OpenPGP.pgp_writer_free(@ref)
    end

    # TODO: allow multiple strings, or bytes as input?
    def write(bytes)
      error = FFI::MemoryPointer.new(:pointer, 1)
      memBuf = FFI::MemoryPointer.new(:char, bytes.bytesize)
      memBuf.put_bytes(0, bytes)
      val = OpenPGP.pgp_writer_write(error, @ref, memBuf, bytes.bytesize)
      raise Error.new(error.get_pointer(0)) if val < 0
      val
    end
  end
end
