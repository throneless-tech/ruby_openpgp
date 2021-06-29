require_relative "../ruby_openpgp"

if __FILE__ == $PROGRAM_NAME
  key = File.read(ARGV[0])
  message = ARGV[1]
  file = ARGV[2] || nil
  Sequoia::encrypt_for(plaintext: message, recipients: key, outfile: file)
end
