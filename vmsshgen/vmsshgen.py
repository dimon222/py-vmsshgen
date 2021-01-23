import argparse
from pathlib import Path
import logging
import os
import asyncio

from .helpers import generate_public_private_keypair, dispatch_ssh_key

log = logging.getLogger(__name__)


async def process(args):
    name = args.n
    hostname_without_port = args.host.split(":")[0]
    home = str(Path.home())
    if not os.path.exists(f"{home}/.ssh"):
        os.mkdir(f"{home}/.ssh")

    if os.path.exists(f"{home}/.ssh/{name}.pem"):
        raise Exception(
            f"There's already private key in {home}/.ssh/{name}.pem, please remove it first"
        )

    private_key, public_key = await generate_public_private_keypair(
        args.algo,
        args.key_size,
        args.exponent,
        args.passphrase,
        args.cipher,
        args.rounds,
        args.hash_name,
    )

    password_key = open(args.pf).read().strip()
    await dispatch_ssh_key(args.host, args.lt, args.username, password_key, public_key)

    with open(f"{home}/.ssh/{name}.pem", "wb") as file_out:
        file_out.write(private_key)

    os.chmod(f"{home}/.ssh/{name}.pem", 0o700)

    with open(f"{home}/.ssh/config", "a") as file_out:
        s = f"\nHost {hostname_without_port}\nHostName {hostname_without_port}\nUser {args.username}\nIdentityFile {home}/.ssh/{name}.pem\nIdentitiesOnly yes\nPreferredAuthentications publickey\n\n"
        file_out.write(s)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "host", type=str, help="VM hostname:port (example localhost:22)"
    )
    parser.add_argument(
        "lt", type=str, choices=["password", "privatekey"], help="login type"
    )
    parser.add_argument("username", type=str, help="VM username")
    parser.add_argument("pf", type=str, help="Password file location")
    parser.add_argument(
        "-n", "--name", dest="n", type=str, help="name for public/private key"
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        dest="algo",
        type=str,
        default="ssh-ed25519",
        help="algorithm for keypair (default is ssh-ed25519)",
    )
    parser.add_argument(
        "-ks",
        "--key-size",
        dest="key_size",
        type=int,
        default=None,
        help="key size (only for RSA)",
    )
    parser.add_argument(
        "-e",
        "--exponent",
        dest="exponent",
        type=int,
        default=None,
        help="exponent (only for RSA)",
    )
    parser.add_argument(
        "-p",
        "--passphrase",
        dest="passphrase",
        type=int,
        default=None,
        help="passphrase for OpenSSH key (default is None)",
    )
    parser.add_argument(
        "-c",
        "--cipher",
        dest="cipher",
        type=str,
        default="aes256",
        help="cipher for OpenSSH key (default is aes256)",
    )
    parser.add_argument(
        "-r",
        "--rounds",
        dest="rounds",
        type=int,
        default=128,
        help="rounds for OpenSSH key (default is 128)",
    )
    parser.add_argument(
        "-hn",
        "--hash-name",
        dest="hash_name",
        type=str,
        default="sha256",
        help="hash name for OpenSSH key (default is sha256)",
    )
    # parser.add_argument("-v", "--verbosity", dest='v', type=int,
    #                    help="increase output verbosity")
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(process(args))
    except KeyboardInterrupt:
        loop.stop()
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        asyncio.set_event_loop(None)
        loop.close()


if __name__ == "__main__":
    main()
