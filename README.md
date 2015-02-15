# soft-pkcs11

soft-pkcs11 is a software only pkcs11 implementation. The main idea is to be adble to turn your phone into secure keychain. But you can use this module as you wish.

It is inspired by soft-pkcs11(http://people.su.se/~lha/soft-pkcs11/README) implementation by Love Hörnquist Åstrand(http://people.su.se/~lha/) and includes it as an example.

It only handles RSA, this is because I use it for ssh-agent.

It is not production-ready yet but I'am using it every day. 


## Features

* Can working with simple folder with keys
* Can work with remote folder assesbile through fuse(sshfs for ex.)
* Can bind together private and public keys by public modulus or filename convention(.pub after private key name)
* Ssh to openssl pubkey convertion
* Can use encfs to transparently encrypt/decrypt keys
* Can use openssl to transparently encrypt/decrypt keys
* Can use ANY script to transparently encrypt/decrypt keys
* Can use many transport/encryption layers: openssl over encfs over sshfs....
* No data stored in memory or copied to computer
* easy(but on C++) to extend transport protocol to be able to use with HTTP or FTP or any other


## PKCS11 Features

* Create object(type determined byt content so 'data' must be used on creation)
* Read object(pubkey, privkey and data)
* Sign(used by ssh to establish connection)


## Usage
I'am using it with my android phone to make it my keychain. All keys stored on my phone in encrypted form(openssl/enfs/md-crypt).
They are mounted to local folder with fuse sshfs. And they are accessible only for my user(even root can't access mounted fs).
After mouting encrypted keys they mounts through another fuse module encfs to another folder and makes unencrypted.
But you still must use RSA private key encryption. So I can use my phone with ssh or ssh-agent.

This is very easy: 
```Shell
eval `ssh-agent`
ssh-add -s `pwd`/./libsoft-pkcs.so
````
Well done.


## Config Examples

SOFTPKCS11RC enviroment variable or $HOME/.soft-token.rc used to configure module.
All drivers are stacked in order as they appeared in config.


### Local folder with encrypted keys
```INI
[fs any label]
#simple filesystem driver so you already can use soft-pkcs11 to expose keys is folder
driver=fs
path=/home/jerry/devel/soft-pkcs/keys

[openssl encryption]
driver=crypt
#%PIN% substituted when token logged in with pin
decrypt=/usr/bin/openssl enc -d -base64 -aes-256-cbc -k '%PIN%'
encrypt=/usr/bin/openssl enc -base64 -aes-256-cbc -k '%PIN%'
```


With this config key files stored in `/home/jerry/devel/soft-pkcs/keys` encrypted as specified in `[openssl encryption]` block. Pin used as password for encryption.

### Remote Android FS with encfs

```INI
[android fs]
driver=fuse
#this is simple password to access my phone through ssh. It is simple because SFTP server is not always run.
mount=echo "123123123" | sshfs -o password_stdin root@android:/mnt/sdcard/keys /home/jerry/.soft-pkcs11/sshfs &> /dev/null
umount=fusermount -u /home/jerry/.soft-pkcs11/sshfs &> /dev/null
#if you don't want to use encryption you can use module already.
path=/home/jerry/.soft-pkcs11/sshfs

[encryption layer]
driver=fuse
#password(pin) ALWAYS written to stdin with 'fuse' driver
#setting up encfs(.encfs6.xml) is made by hand
mount=encfs -S /home/jerry/.soft-pkcs11/sshfs /home/jerry/.soft-pkcs11/keys  &> /dev/null
umount=fusermount -u /home/jerry/.soft-pkcs11/keys  &> /dev/null
path=/home/jerry/.soft-pkcs11/keys
```

You can combine driver layers.


# Usage

To manage keys through soft-pkcs11 module you can use `pkcs11-tool` from `opensc`  package:
```Shell
jerry@jerry ~/devel/soft-pkcs/build $ pkcs11-tool --module ./libsoft-pkcs.so -O -l -p 123123123 
Using slot 0 with a present token (0x1)
Public Key Object; RSA 0 bits
  label:      SSH ssh-private.key.pub
  ID:         32303834333137323432393530393938333731
  Usage:      encrypt, verify
Private Key Object; RSA 
  label:      ssh-private.key
  ID:         3130383437353832373236323639373335323836
  Usage:      decrypt, sign, unwrap
  Access:     always authenticate
Private Key Object; RSA 
  label:      ssl-private.key
  ID:         3133313438313534303736313735313537333832
  Usage:      decrypt, sign, unwrap
  Access:     always authenticate
Public Key Object; RSA 0 bits
  label:      ssh-private.key.pub
  ID:         3130383437353832373236323639373335323836
  Usage:      encrypt, verify


pkcs11-tool --module ./libsoft-pkcs.so -l -p 123123123 -r -y privkey -a ssh-private.key
```

To use it with ssh: 

```Shell
jerry@jerry ~/devel/soft-pkcs/build $ eval `ssh-agent`
Agent pid 12930
jerry@jerry ~/devel/soft-pkcs/build $ ssh-add -s `pwd`/libsoft-pkcs.so 
Enter passphrase for PKCS#11: <123123123>
Card added: /home/jerry/devel/soft-pkcs/build/./libsoft-pkcs.so
jerry@jerry ~/devel/soft-pkcs/build $ ssh jerry@localhost                   
jerry@jerry ~ SSH
```



## Security

* There is no data stored in module memory except pin. But data can be stored in underlying fs cache or something else. Data transmitted to the module in initialization and only public metadata stored(label, size, public modulus...). Another data transmittion happens when you `read` key/data contents or use `sign/encrypt` which are implemeted through OpenSsl. 
* You can use any underlying crypto-tools like dm-crypt, sshfs, encfs, gpg-crypt and other, so they are responsible for whole security. 
* It is strongly recommended to use RSA-encrycted private keys.
 



