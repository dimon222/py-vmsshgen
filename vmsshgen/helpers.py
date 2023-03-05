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
            await ssh_connection.chdir("~")
            relative_ssh_folder_path = ".ssh"
            relative_authorized_keys_path = f"{relative_ssh_folder_path}/authorized_keys"
            is_folder_present = await sftp_connection.exists(relative_ssh_folder_path)
            if not is_file_present:
                await sftp_connection.mkdir(relative_ssh_folder_path)
                await sftp_connection.chmod(relative_ssh_folder_path, 700)
            is_file_present = await sftp_connection.exists(relative_authorized_keys_path)
            file_pointer = None
            if is_file_present:
                file_pointer = await sftp_connection.open(relative_authorized_keys_path, "a")
            else:
                file_pointer = await sftp_connection.open(relative_authorized_keys_path, "w")
                await file_pointer.chmod(600)
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
