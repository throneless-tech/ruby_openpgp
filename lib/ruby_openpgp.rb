# frozen_string_literal: true

require_relative "ruby_openpgp/version"
require_relative "ruby_openpgp/encrypt"
require_relative "ruby_openpgp/decrypt"
require_relative "sequoia_openpgp"

module RubyOpenPGP
  class Error < StandardError; end
  # Your code goes here...
end
