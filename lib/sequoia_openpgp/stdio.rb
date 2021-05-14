require "ffi"

module Stdio
    extend FFI::Library
    ffi_lib FFI::Platform::LIBC
    Malloc = attach_function :malloc, [:size_t], :pointer
    Free = attach_function :free, [:pointer], :void
end
