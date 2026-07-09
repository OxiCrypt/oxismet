# OxiSMET
This is OxiSMET(OxiCrypt Server Mass Encryption Tool)
It is tailored for servers
## Why OxiSMET?
* Small Codebase.
With OxiSMET, you have a tiny codebase consisting of the bare essentials and nothing more.
* 100% compatibility.
I am building OxiSMET from the ground up so no change is ever breaking. ALl legacy formats will be supported, as the version section of the header will be a full 8 bytes
* Full Headlessness
Coming into this project, there is a major selling point: Headlessness. It can operate from a bash script, POSIX sh, or anything capable of running a command.
Library is available so that any Rust program can call upon OxiSMET to outsource the heavy lifting.
## Security Notes
* Not suitable for operation on processors that do not have Constant-Time multiplication
* Uses the following primitives, with the crate providing said primitive in parentheses: AES-GCM(aes-gcm), Argon2(argon2)
* Does not use any libraries outside aes-gcm, argon2, rand, zeroize, and std
