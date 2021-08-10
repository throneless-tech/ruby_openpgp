require_relative "../../lib/openpgp"
require "test/unit"
require "ffi"
require "stringio"

class TestIOWriter < Test::Unit::TestCase
  def test_from_bytes
    length = 8
    memBuf = FFI::MemoryPointer.new(:char, length)
    writer = OpenPGP::IOWriter.new_from_bytes(memBuf)
    writer.write("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    assert_equal(
      "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb".b,
      memBuf.get_bytes(0, length)
    )
  end

  def test_from_callback
    str = 'Feminism is great!'
    buffer = StringIO.new
    writer = OpenPGP::IOWriter.new_from_callback(buffer)
    writer.write(str)
    buffer.rewind
    assert_equal(str, buffer.read)
  end

  def test_from_fd
    str = "Hello world!"
    filepath = 'test/unit/data/iowriter_test.txt'
    file = File.open(filepath, 'w')
    writer = OpenPGP::IOWriter.new_from_fd(file.fileno)
    writer.write(str)
    file.close
    reader = OpenPGP::IOReader.new_from_file(filepath)
    assert_equal(str, reader.read(12))
    File.delete(filepath)
  end

  def test_from_file
    str = "Hello world!"
    filepath = 'test/unit/data/iowriter_test.txt'
    writer = OpenPGP::IOWriter.new_from_file(filepath)
    writer.write(str)
    reader = OpenPGP::IOReader.new_from_file(filepath)
    assert_equal(str, reader.read(12))
    File.delete(filepath)
  end

  def test_write
    str = "Hello world!"
    filepath = 'test/unit/data/iowriter_test.txt'
    writer = OpenPGP::IOWriter.new_from_file(filepath)
    writer.write("")
    writer.write(str[0,5])
    writer.write(str[5,11])
    writer.write(str[11,])
    reader = OpenPGP::IOReader.new_from_file(filepath)
    assert_equal(str, reader.read(12))
    File.delete(filepath)
  end
end

class TestIOReader < Test::Unit::TestCase
  def test_from_bytes
    reader = OpenPGP::IOReader.new_from_bytes("\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb")
    assert_equal("\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB".b, reader.read(8))
  end

  def test_from_callback
    str = 'blub'
    buffer = StringIO.new
    buffer.write(str)
    buffer.rewind
    reader = OpenPGP::IOReader.new_from_callback(buffer)
    assert_equal(str, reader.read)
  end

  def test_from_fd
    fd = File.open('test/unit/data/ioreader_test.txt', 'r').fileno
    reader = OpenPGP::IOReader.new_from_fd(fd)
    assert_equal("Hello world!", reader.read(12))
  end

  def test_from_file
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    assert_equal("Hello world!", reader.read(12))
  end

  def test_from_file_error
    assert_raise OpenPGP::IOError do
      OpenPGP::IOReader.new_from_file('non-existent.txt')
    end
  end

  def test_copy
    # create a writer to copy to
    buffer = StringIO.new
    writer = OpenPGP::IOWriter.new_from_callback(buffer)

    # create reader
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    reader.copy(writer, 12)
    buffer.rewind
    assert_equal("Hello world!", buffer.read)
  end

  def test_discard
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    reader.discard()
    assert_equal("", reader.read)
    assert_equal(nil, reader.read(10))
  end

  def test_read_length
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    assert_equal("", reader.read(0))
    assert_equal("Hello", reader.read(5))
    assert_equal(" world!\n", reader.read(10))
    reader.discard
    assert_equal(nil, reader.read(1))
  end

  def test_read_all
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    assert_equal("Hello world!\n", reader.read)
    assert_equal("", reader.read)
  end

  def test_read_length_outbuf
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    outbuf = ""
    assert_equal("Hello", reader.read(5, outbuf))
    assert_equal("Hello", outbuf)
    reader.discard
    assert_equal(nil, reader.read(1, outbuf))
    assert_equal("", outbuf)
  end

  def test_read_all_outbuf
    reader = OpenPGP::IOReader.new_from_file('test/unit/data/ioreader_test.txt')
    outbuf = ""
    assert_equal("Hello world!\n", reader.read(nil, outbuf))
    assert_equal("Hello world!\n", outbuf)
    assert_equal("", reader.read(nil, outbuf))
    assert_equal("", outbuf)
  end
end
