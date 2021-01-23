import asyncssh


async def dispatch_ssh_key(host_port, logintype, username, password_key, public_key):
    host, port = host_port.split(":")
    options = None
    if logintype == "password":
        options = asyncssh.SSHClientConnectionOptions(
            known_hosts=None, username=username, password=password_key
        )
    elif logintype == "privatekey":
        options = asyncssh.SSHClientConnectionOptions(
            known_hosts=None,
            client_username=username,
            client_keys=[asyncssh.import_private_key(password_key)],
        )

    async with asyncssh.connect(host, int(port), options=options) as ssh_connection:
        async with ssh_connection.start_sftp_client() as sftp_connection:
            is_file_present = await sftp_connection.exists(".ssh/authorized_keys")
            file_pointer = None
            if is_file_present:
                file_pointer = await sftp_connection.open(".ssh/authorized_keys", "a")
            else:
                file_pointer = await sftp_connection.open(".ssh/authorized_keys", "w")
            await file_pointer.write(public_key)
            await file_pointer.close()

            # potentially_set_chmod(authorized_keys)
            # potentially_update_sshd_settings_and_restart_it()


async def generate_public_private_keypair(
    algo, key_size, exponent, passphrase, cipher, rounds, hash_name
):
    if algo == "ssh-rsa":
        _private_key = asyncssh.generate_private_key(
            algo, key_size=key_size, exponent=exponent
        )
    else:
        _private_key = asyncssh.generate_private_key(algo)
    private_key = _private_key.export_private_key(
        "openssh",
        passphrase=passphrase,
        cipher_name=cipher,
        hash_name=hash_name,
        rounds=rounds,
    )
    public_key = _private_key.export_public_key("openssh")
    return private_key, public_key.decode("utf-8")
