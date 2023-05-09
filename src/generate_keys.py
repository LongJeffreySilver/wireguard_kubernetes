
import subprocess

#wg genkey | tee private_key.key | wg pubkey > public_key.key.pub
#launch with sudo or sudo su

file = open('/etc/wireguard/public_key.key.pub', 'w')

processWg = subprocess.Popen(["wg", "genkey"], stdout=subprocess.PIPE)

processTee = subprocess.Popen(["tee", "private_key.key"], stdin=processWg.stdout, stdout=subprocess.PIPE) 

processPubkey = subprocess.Popen(["wg","pubkey"], stdin=processTee.stdout, stdout=file)

processChmod = subprocess.Popen(["chmod", "600", "private_key.key", "public_key.key.pub" ])