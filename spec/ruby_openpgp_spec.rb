# frozen_string_literal: true

RSpec.describe RubyOpenpgp do
  it "has a version number" do
    expect(RubyOpenpgp::VERSION).not_to be nil
  end

  it "does something useful" do
    expect(false).to eq(true)
  end

  # it decrypts a message
  # it encrypts a message
  # it verifies keys for sender
  # its verifies keys for recipient
end
