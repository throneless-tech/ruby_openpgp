require_relative "../ruby_openpgp"

if __FILE__ == $PROGRAM_NAME
  file = ARGV[0]
  key = File.read(ARGV[1])
  puts Sequoia::decrypt_file_for(infile: file, recipient: key)
end
