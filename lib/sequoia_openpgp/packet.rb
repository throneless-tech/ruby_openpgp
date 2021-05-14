require "ffi"
require "objspace"

require_relative "./stdio"

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :packet
  attach_function :pgp_packet_clone, [:packet], :packet
  attach_function :pgp_packet_debug, [:packet], :strptr
  attach_function :pgp_packet_equal, [:packet, :packet], :bool
  attach_function :pgp_packet_free, [:packet], :void
  attach_function :pgp_packet_hash, [:packet], :uint64
  attach_function :pgp_packet_kind, [:packet], :uint8
  attach_function :pgp_packet_tag, [:packet], :uint8
  attach_function :pgp_tag_to_string, [:uint8], :string

  class Tag
    attr_reader :value

    def initialize(value)
      @value = value
    end

    def to_s
      OpenPGP.pgp_tag_to_string(@value)
    end
  end

  class Packet
    attr_reader :ref

    def initialize(packet)
      @ref = packet
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_packet_free(@ref)
    end

    def clone
      Packet.new(OpenPGP.pgp_packet_clone(@ref))
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_packet_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def ==(other)
      OpenPGP.pgp_packet_equal(@ref, other.ref)
    end

    def eql?(other)
      OpenPGP.pgp_packet_equal(@ref, other.ref)
    end

    def hash
      OpenPGP.pgp_packet_hash(@ref)
    end

    def kind
      kind = OpenPGP.pgp_packet_kind(@ref)
      if kind == 0
        nil
      else
        Tag.new(kind)
      end
    end

    def tag
      Tag.new(OpenPGP.pgp_packet_tag(@ref))
    end
  end
end
