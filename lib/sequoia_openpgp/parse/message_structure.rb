require "ffi"
require "objspace"

require_relative '../stdio'
require_relative './verification_result'

module OpenPGP
  extend FFI::Library
  ffi_lib 'libsequoia_openpgp_ffi'

  typedef :pointer, :message_structure
  typedef :pointer, :message_structure_iter
  typedef :pointer, :message_layer

  attach_function :pgp_message_layer_compression, [:message_layer, :pointer], :bool
  attach_function :pgp_message_layer_encryption, [:message_layer, :pointer, :pointer], :bool
  attach_function :pgp_message_layer_free, [:message_layer], :void
  attach_function :pgp_message_layer_signature_group, [:message_layer, :verification_result_iter], :bool
  attach_function :pgp_message_layer_variant, [:message_layer], :int
  attach_function :pgp_message_structure_free, [:message_structure], :void
  attach_function :pgp_message_structure_debug, [:message_structure], :strptr
  attach_function :pgp_message_structure_into_iter, [:message_structure], :message_structure_iter
  attach_function :pgp_message_structure_iter_free, [:message_structure_iter], :void
  attach_function :pgp_message_structure_iter_next, [:message_structure_iter], :message_layer

  class MessageLayer
    def initialize(layer)
      @ref = layer
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_message_layer_free(@ref)
    end

    def compression
      algo_ptr = FFI::MemoryPointer.new(:uint8, 1)
      ret = OpenPGP.pgp_message_layer_compression(@ref, algo_ptr)
      return ret, algo_ptr.get_uint8(0)
    end

    def encryption
      OpenPGP.pgp_message_layer_encryption(@ref, nil, nil)
    end

    def signature_group
      results = FFI::MemoryPointer.new(:pointer, 1)
      ret = OpenPGP.pgp_message_layer_signature_group(@ref, results)
      if ret
        return VerificationResultIter.new(results.get_pointer(0))
      end
    end

    # 1: compression, 2: encryption, 3: signaturegroup
    def variant
      OpenPGP.pgp_message_layer_variant(@ref)
    end
  end

  class MessageStructureIter
    include Enumerable

    def initialize(iter)
      @ref = iter
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_message_structure_iter_free(@ref)
    end

    def each(&block)
      while layer = next_layer
        yield layer
      end
    end

    def next_layer
      layer = OpenPGP.pgp_message_structure_iter_next(@ref)
      MessageLayer.new(layer) unless layer.null?
    end
  end

  class MessageStructure
    def initialize(message_structure)
      @ref = message_structure
      ObjectSpace.define_finalizer(self, self.method(:release).to_proc)
    end

    def release
      OpenPGP.pgp_message_structure_free(@ref)
    end

    def to_debug_s
      str, ptr = OpenPGP.pgp_message_structure_debug(@ref)
      Stdio.free(ptr)
      str
    end

    def layers
      MessageStructureIter.new(OpenPGP.pgp_message_structure_into_iter(@ref))
    end
  end
end
