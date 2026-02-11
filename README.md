# Read.Write
the read.write project

This is a cross-language projects showcasing read and write operations within memory, Also allowing users to get max privileges on their project

Implemented in Go, Powershell, Python, Rust

In Progress: VBScript (DynamicWrapperX)

Pending: C++ (Usermode/Kernelmode/Bootkit), C, C#, Swift, Zig, Java, Kotlin,
         AHK, AutoIt, DarkBasic, Perl, Ruby, PHP, Lua, Node.js, Excel, DMA

## Features
- Read from and write to memory
- Read from and write to the console
- Consistent API across multiple languages

## Usage Example

All implementations provide similar functions for reading and writing. Here is a common usage pattern:

1. Write a value to memory
2. Read the value from memory
3. Print the value to the console

### Example (Pseudocode)

```pseudo
memory.write("key", "Hello, World!")
value = memory.read("key")
console.write(value)
```

Refer to each language's folder for specific usage instructions.

