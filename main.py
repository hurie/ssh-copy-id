import argparse
import getpass
import logging
import sys
import threading
from multiprocessing.pool import ThreadPool
from pathlib import Path

import paramiko
import yaml
from paramiko import AuthenticationException

CONFIG_FILE = 'ssh-copy-id.yaml'
POOL_SIZE = 10


def print_std(*stds, prefix=None):
    for std in stds:
        lines = std.read().decode().strip().splitlines(keepends=False)
        for line in lines:
            if prefix:
                print('%s: %s' % (prefix, line))
            else:
                print(line)


read_password_lock = threading.Lock()
read_password_pass = None


def read_password(force=False):
    global read_password_pass

    if not force and read_password_pass is not None:
        return read_password_pass

    read_password_lock.acquire()
    try:
        if not force and read_password_pass is not None:
            return read_password_pass

        read_password_pass = getpass.getpass(stream=sys.stdout)
    except KeyboardInterrupt:
        read_password_pass = False
    finally:
        read_password_lock.release()

    return read_password_pass


def process(username, password, pubkey, hostname):
    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)

        try:
            logging.info('%s: connect ke %s@%s pakai agent', hostname, username, hostname)
            client.connect(hostname, username=username)
        except AuthenticationException:
            while True:
                logging.info('%s: connect ke %s@%s pakai password', hostname, username, hostname)

                if password is None:
                    password = read_password()
                elif password is False:
                    password = read_password(True)

                if password is False:
                    logging.warning('%s: dibatalkan', hostname)
                    return

                try:
                    client.connect(hostname, username=username, password=password, allow_agent=False)
                    break
                except AuthenticationException as e:
                    password = False
                    logging.error('%s: gagal login menggunakan password (%s)', hostname, e)

        sftp = client.open_sftp()

        chcon = False
        try:
            sftp.lstat('.ssh')
        except FileNotFoundError:
            logging.info('%s: mkdir .ssh', hostname)
            sftp.mkdir('.ssh', mode=0o700)
            chcon = True

        auth_key = '.ssh/authorized_keys'
        try:
            f = sftp.open(auth_key, mode='r+')
        except FileNotFoundError:
            stdin, stdout, stderr = client.exec_command('echo -n > %s' % auth_key)
            print_std(stdout, stderr)

            f = sftp.open(auth_key, mode='a+')

        lines = f.read().splitlines(False)
        if pubkey.encode() not in lines:
            logging.info('%s: upload pubkey to %s', hostname, auth_key)
            f.write("%s\n" % pubkey)

        stat = f.stat()
        if stat.st_mode & 0x3FF != 0o600:
            logging.info('%s: chmod %s (%o)', hostname, auth_key, stat.st_mode & 0x3FF)
            f.chmod(0o600)

        if chcon:
            logging.info('%s: chcon .ssh', hostname)
            stdin, stdout, stderr = client.exec_command('chcon -R -t ssh_home_t .ssh')
            print_std(stdout, stderr)

    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(prog='ssh-copy-id')
    parser.add_argument('-c', '--config', type=Path, help='file konfigurasi')
    parser.add_argument('-u', '--username', type=str, help='username untuk setup pubkey login')
    parser.add_argument('-p', '--password', default=False, action='store_true', help='prompt untuk mengisi password')
    parser.add_argument('-k', '--pubkey', type=Path, help='publik key yang akan dikirim')
    parser.add_argument('-n', '--concurrency', type=int, default=POOL_SIZE, help='jumlah proses pool untuk eksekusi')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('host', type=str, nargs='*', help='host')

    args = parser.parse_args()
    if not args.host and not args.config:
        parser.error('File konfigurasi atau host tidak boleh kosong')

    if args.verbose == 0:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger('paramiko').setLevel(logging.WARN)

    elif args.verbose == 1:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.WARN)

    elif args.verbose == 2:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.INFO)

    elif args.verbose >= 3:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger('paramiko').setLevel(logging.DEBUG)

    address = args.host
    username = getpass.getuser()
    password = None
    pubkey = None

    if args.config is None:
        file_cfg = Path(CONFIG_FILE)
        if file_cfg.exists():
            logging.info('pakai defualt konfig %s', CONFIG_FILE)
            with file_cfg.open() as f:
                cfg = yaml.safe_load(f)

            pubkey = open(cfg['id_pub']).read()
            username = cfg['credential']['username']

    else:
        if not args.config.exists():
            parser.error('%s tidak ditemukan' % args.config)

        with args.config.open() as f:
            cfg = yaml.safe_load(f)

        pubkey = open(cfg['id_pub']).read()
        username = cfg['credential']['username']
        password = cfg['credential']['password']

        address.extend(cfg['addresses'])

        pubkey = pubkey.strip()

    if not args.password and password is None:
        parser.error('Password tidak ditemukan')

    if args.pubkey is None and pubkey is None:
        parser.error('Pubkey tidak ditemukan')

    if args.username:
        username = args.username

    if args.pubkey:
        if not args.pubkey.exists():
            parser.error('%s tidak ditemukan' % args.pubkey)
        pubkey = args.pubkey.read_text()
        pubkey = pubkey.strip()

    concurrency = min(len(address), args.concurrency)
    with ThreadPool(processes=concurrency) as pool:
        results = []
        for hostname in address:
            result = pool.apply_async(process, (username, password, pubkey, hostname))
            results.append(result)

        for result in results:
            result.get()


if __name__ == '__main__':
    main()
