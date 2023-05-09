#! /usr/bin/env python3

import logging
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, BlockedStatus
import time
import subprocess

logger = logging.getLogger(__name__)

class wgServices(CharmBase):

    def __init__(self, *args) -> None:
        self.server_name = "wg0"
        self.free_IP_list = list()
        for i in range(1,11):
            ip = "192.168.1."
            aux = 200 + i
            ip = ip + str(aux)
            self.free_IP_list.append(ip)

        """Initialize charm and configure states and events to observe."""
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self.configure_pod)
        self.framework.observe(self.on.init_config_action, self._on_init_config_action)
        self.framework.observe(self.on.get_server_data_action,self._on_get_server_data_action)
        self.framework.observe(self.on.add_client_action, self._on_add_client_action)
        self.framework.observe(self.on.dissconnect_client_action, self._on_dissconnect_client_action)


    def checkInterface(self, interface_list):
        result = subprocess.run(["ls","/sys/class/net"], check=True, capture_output=True, text=True)
        output = result.stdout.split('\n')
        interface = ""
        for interface in output: #Wired: en (enps1, eno1 or ens1) and eth (eth0) | Wifi: wl (wlan wlp)
            if (("en" in interface) or ("wl" in interface)  or ("eth" in interface)) and (len(interface) < 8):
            
                for current_interface in interface_list:
                    if current_interface in interface:
                        interface_path = "/sys/class/net/" + interface + "/operstate"
                        cat_process = subprocess.Popen(["cat", interface_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,text=True)
                        output,err = cat_process.communicate()
                        interface_status = output.split(sep="\n")
                        if interface_status[0] == "up":
                            return interface                    
        return "-1"

    def generate_keys(self):
        file = open('/etc/wireguard/public_key.key.pub', 'w')

        processWg = subprocess.Popen(["wg", "genkey"], stdout=subprocess.PIPE)

        processTee = subprocess.Popen(["tee", "/etc/wireguard/private_key.key"], stdin=processWg.stdout, stdout=subprocess.PIPE) 

        processPubkey = subprocess.Popen(["wg","pubkey"], stdin=processTee.stdout, stdout=file)

        processChmod = subprocess.Popen(["chmod", "600", "/etc/wireguard/private_key.key", "/etc/wireguard/public_key.key.pub" ])

        file.close()
        time.sleep(3)

    def _on_init_config_action(self, event):
        self.generate_keys()
        interface_list = ["enp","eno","ens","eth"]
        iface_name = self.checkInterface(interface_list)
        server_listening_port = "41194"
        if(iface_name != None):
            try:
                file_server_priv_key = open("/etc/wireguard/private_key.key",'r')
                server_priv_key = file_server_priv_key.readline()
                file_server_priv_key.close()

                conf_file = open("/etc/wireguard/"+ self.server_name + ".conf","w")
                conf_file.write(
                "[Interface]\n"
                + "Address = 192.168.1.200\n"
                + "PrivateKey = " + server_priv_key
                + "ListenPort = " + server_listening_port + "\n"
                + "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o " + iface_name + " -j MASQUERADE\n"## Cambiar la interfaz de red enp0s3 por la que tenga el servidor
                + "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o " + iface_name + "-j MASQUERADE" ## Cambiar la interfaz de red enp0s3 por la que tenga el servidor
                )
                conf_file.close()

                subprocess.Popen(["systemctl", "start", "wg-quick@" + self.server_name])
                time.sleep(5)

                wg_command = subprocess.run(["sudo", "wg"], capture_output=True, text=True)
                wg_text = wg_command.stdout.splitlines()

                event.set_results({
                    "output": f"Server started successfully: \n {wg_text}"
                })

            except Exception as e:
                event.fail(f"Server initiation failed due an unespected exception named: {e}")
        else:
            event.fail(f"Server initiation failed due a problem with network interfaces: {e}")

    def _on_get_server_data_action(self, event):
        try:

            wg_command = subprocess.run(["sudo", "wg"], capture_output=True, text=True)
            wg_text = wg_command.stdout.splitlines()
            
            process_dig = subprocess.run(["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], capture_output=True, text=True)
            server_public_ip = process_dig.stdout.splitlines()[0]
            event.set_results({
                    "output": f"Server with public IP {server_public_ip} started successfully: \n {wg_text}"
            })
        except Exception as e:
            event.fail(f"Server data failed due an unespected exception named: {e}")

    def _on_add_client_action(self, event): #El cliente pasa su clave publica y se le genera una IP privada. Ademas, ya se le añade con esa IP privada
        try:
            
            client_ip = self.free_IP_list.pop(0)
            client_key_string = event.params["public_key"]
            server_conf_file = open("/etc/wireguard/"+ self.server_name + ".conf","a")
            new_client = "\n[Peer]\n" + "PublicKey = " + client_key_string + "\n"+ "AllowedIPs = " + client_ip + "/32\n" + "PersistentKeepAlive = 25\n" + "\n"

            server_conf_file.write(new_client)

            server_conf_file.close()
            time.sleep(5)
            subprocess.Popen(["systemctl", "restart", "wg-quick@" + self.server_name])
            time.sleep(5)

            event.set_results({
                    "output": f"This is your private IP: {client_ip}/32\n Client added\n"
            })
        except Exception as e:
            event.fail(f"Server failed due an unespected exception named: {e}")

    def _on_dissconnect_client_action(self, event):
        
        try:
            client_key_string = event.params["public_key"]
            client_priv_ip = event.params["ip"]
            with open(self.server_name, "r") as server_conf_file:
                lines = server_conf_file.readlines()
            index = 0
            is_client = False
            for line in lines:
                if client_key_string in line:
                    key_index = index
                    if client_priv_ip in lines[key_index+1]:
                        key_index -= 1
                        for i in range(0,5):
                            lines.pop(key_index)
                        is_client = True
                        continue
                index += 1
            with open(self.server_name, "w") as server_conf_file:
                for line in lines:
                    server_conf_file.write(line)
            
            if(is_client == True):
                event.set_results({
                    "output": f"Client removed\n"
                })
            else:
                event.set_results({
                    "output": f"Client data is not correct. Please, check the params.\n"
                })
        except Exception as e:
            event.fail(f"Server failed due an unespected exception named: {e}")


    def configure_pod(self, event):
        if not self.unit.is_leader():
            self.unit.status = ActiveStatus()
            return
        self.unit.status = MaintenanceStatus("Applying pod spec")
        containers = [
            {
                "name": self.framework.model.app.name,
                "image": "jeffreysilver/wireguard_server:latest",
                "ports": [
                    {
                        "name": "wireguard",
                        "containerPort": 41194,
                        "protocol": "UDP",
                    }
                    ,
                    {   
                        "name": "iptnetflow",
                        "containerPort": 22,
                        "protocol": "TCP",
                    }
                ],
                #"command": ["/usr/sbin/init"],
                "command": ["/bin/bash","-ce"], #"/usr/sbin/init & tail -f /dev/null"
                "args": ["tail -f /dev/null && /usr/sbin/init"],
                "kubernetes": { "securityContext": { "privileged": True}}
            }
        ]

        kubernetesResources = {"pod": {"hostNetwork": True}}

        self.model.pod.set_spec({"version": 3, "containers": containers, "kubernetesResources": kubernetesResources})

        self.unit.status = ActiveStatus()
        self.app.status = ActiveStatus()

if __name__ == "__main__":
    main(wgServices)
