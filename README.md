# py-vmsshgen
Automatic generation of SSH keys for VM.

## Why?
I got tired of provisioning SSH keys manually between hundreds of VMs that I had to use.

## How to use?
The script generates OpenSSH keypair and pushes public key to VM using existing SSH connection that can be protected by password (or some another SSH key). The private key on client machine (that executes this application) automatically goes to `~/.ssh/{name}.pem` + reference to it is appended to `~/.ssh/config` for automatic pickup by SSH client configuration.

Supported parameters for key generation - https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.generate_private_key   
Supported parameters for private key export - https://asyncssh.readthedocs.io/en/latest/api.html#asyncssh.SSHKey.export_private_key

Default settings:
* Algo for generation - ssh-ed25519
* No passphrase
* Output private key with cipher AES256 with SHA256 hashing and 128 rounds of bcrypt.

You can install it using pip  
`pip install vmsshgen`

All actions are done interactively in terminal:  
```
usage: vmsshgen [-h] [-n N] [-a ALGO] [-ks KEY_SIZE] [-e EXPONENT] [-p PASSPHRASE] [-c CIPHER] [-r ROUNDS] [-hn HASH_NAME] host {password,privatekey} username pf

positional arguments:
  host                  VM hostname:port (example localhost:22)
  {password,privatekey}
                        login type
  username              VM username
  pf                    Password file location

optional arguments:
  -h, --help            show this help message and exit
  -n N, --name N        name for public/private key
  -a ALGO, --algorithm ALGO
                        algorithm for keypair (default is ssh-ed25519)
  -ks KEY_SIZE, --key-size KEY_SIZE
                        key size (only for RSA)
  -e EXPONENT, --exponent EXPONENT
                        exponent (only for RSA)
  -p PASSPHRASE, --passphrase PASSPHRASE
                        passphrase for OpenSSH key (default is None)
  -c CIPHER, --cipher CIPHER
                        cipher for OpenSSH key (default is aes256)
  -r ROUNDS, --rounds ROUNDS
                        rounds for OpenSSH key (default is 128)
  -hn HASH_NAME, --hash-name HASH_NAME
                        hash name for OpenSSH key (default is sha256)
```

Example with password file on [linuxserver.io](https://hub.docker.com/r/linuxserver/openssh-server) with password `password` stored in file named `pf`:  
`vmsshgen -n test localhost:2222 password linuxserver.io pf`

Of course, if you want to supply password right inside of same commandline statement, there's an option using FIFO pipe:  
` vmsshgen -n test localhost:2222 password linuxserver.io <(echo 'password')`

(Honestly, if you decided to go with this option, I suggest to  ensure that history for current shell is disabled or you enter `space` in front of command to avoid leaking password in history)
