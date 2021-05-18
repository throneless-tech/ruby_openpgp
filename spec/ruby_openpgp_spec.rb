# frozen_string_literal: true

require_relative "../lib/sequoia_openpgp"

RSpec.describe RubyOpenPGP do
  it "has a version number" do
    expect(RubyOpenPGP::VERSION).not_to be nil
  end

  it "requires sequoia ruby ffi bindings" do
    expect(OpenPGP).not_to be nil
  end

  it "has a class to encrypt a message" do
    expect(RubyOpenPGP::Encrypt).not_to be nil
  end

  it "has a class to decrypt a message" do
    expect(RubyOpenPGP::Decrypt).not_to be nil
  end

  # it decrypts a message
  # it encrypts a message
  # it verifies keys for sender
  # its verifies keys for recipient
end
