require_relative "../../lib/openpgp"
require "test/unit"

class TestArmorWriter < Test::Unit::TestCase
  def test_new
    # create new IOWriter
    filepath = 'test/unit/data/armorwriter.txt'
    ioWriter = OpenPGP::IOWriter.new_from_file(filepath)

    # create ArmorHeader for ArmorWriter
    headers = [["Key0", "Value0"], ["Key1", "Value1"]]

    # create new ArmorWriter with headers
    writer = OpenPGP::ArmorWriter.new(ioWriter, PGP_ARMOR_KIND_FILE, headers)

    # write something
    writer.write("Hello world!")
    writer.finalize

    reader = OpenPGP::IOReader.new_from_file(filepath)

    # check result
    assert_equal(
      "-----BEGIN PGP ARMORED FILE-----\n" \
      "Key0: Value0\n" \
      "Key1: Value1\n\n" \
      "SGVsbG8gd29ybGQh\n=s4Gu\n" \
      "-----END PGP ARMORED FILE-----\n",
      reader.read(1000)
    )
  end
end

class TestArmorReader < Test::Unit::TestCase
  def test_new
    ioReader = OpenPGP::IOReader.new_from_file('test/unit/data/armorreader_test.txt')
    reader = OpenPGP::ArmorReader.new(ioReader, 5)
    assert_equal("Hello world!", reader.read(20))
  end

  def test_from_bytes
    reader = OpenPGP::ArmorReader.new_from_bytes(
      "-----BEGIN PGP ARMORED FILE-----\n\n" \
      "SGVsbG8gd29ybGQh\n=s4Gu\n" \
      "-----END PGP ARMORED FILE-----\n",
      5
    )
    assert_equal("Hello world!", reader.read(20))
  end

  def test_from_file
    reader = OpenPGP::ArmorReader.new_from_file('test/unit/data/armorreader_test.txt', 5)
    assert_equal("Hello world!", reader.read(20))
  end

  def test_from_file_io_error
    assert_raise OpenPGP::IOError do
      OpenPGP::ArmorReader.new_from_file('non_existent.txt', 5)
    end
  end

  def test_discard
    reader = OpenPGP::ArmorReader.new_from_file('test/unit/data/armorreader_test.txt', 5)
    reader.discard()
    assert_equal("", reader.read)
  end

  def test_discard_error
    reader = OpenPGP::ArmorReader.new_from_file('test/unit/data/ioreader_test.txt', 5)
    assert_raise OpenPGP::IOError do
      reader.discard()
    end
  end

  def test_read
    reader = OpenPGP::ArmorReader.new_from_file('test/unit/data/armorreader_test.txt', 5)
    assert_equal("", reader.read(0))
    assert_equal("Hello ", reader.read(6))
    assert_equal("world!", reader.read(10))
  end

  def test_read_error
    reader = OpenPGP::ArmorReader.new_from_file('test/unit/data/ioreader_test.txt', 5)
    assert_raise OpenPGP::IOError do
      reader.read(20)
    end
  end
end
