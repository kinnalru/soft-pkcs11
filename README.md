# soft-pkcs11

soft-pkcs11 is a software only pkcs11 implementation.

It is inspired by soft-pkcs11(http://people.su.se/~lha/soft-pkcs11/README) implementation by Love Hörnquist Åstrand(http://people.su.se/~lha/) and includes it as an example.

It only handles RSA, this is because I use it for ssh-agent.

## Features

* Can working with simple folder with keys
* Can work with remote folder assesbile through fuse(sshfs for ex.)
* Can bind together private and public keys by public modulus or filename convention(.pub after private key name)
* Can use encfs to transparently encrypt/decrypt keys
* Can use openssl to transparently encrypt/decrypt keys
* Can use ANY script to transparently encrypt/decrypt keys
* Can use many transport/encryption layes: openssl over encfs over sshfs....
* No data stored in memory or copied to computer
* easly(but on C++) to extend transport protocol to be able to use with HTTP or FTP or any other

## PKCS11 Features

* Create object(type determined byt content so 'data' must be used on creation)
* Read object(pubkey, privkey and data)
* Sign(used by ssh to establish connection)


## Usage

I'am using it with my android phone to make it my keychain. All keys stored on my phone in encrypted form().
They are mounted to local folder with fuse sshfs. And accessible only for my user(even root can't access mounted fs).
After mouting encrypted mounts through another fuse module encfs to another folder and make it unencrypted.
But you still must use RSA private key encryption. So I can use my phone with ssh or ssh-agent.

## Examples

### Remote Android FS


