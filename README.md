# Overview

This repository contains the [Juju](https://juju.is/about) definition for the creation of functional proxy charms. These types of charms implement the communication with the xNF image deployed, triggering commands and actions into the xNF and retrieving internal information from the instance.

# Usage
```shell
# Clone this repository
git clone https://github.com/palantir-h2020/sc-secaas.git
cd sc-secaas/juju-charm

# Setup test scenario
bash test-k8s.sh
bash test-juju.sh

# Pack juju charm
cd juju-charms/iptnetflow
charmcraft pack

# Examine the juju charm and .charm file generated
ls
actions.yaml     metadata.yaml         requirements.in   iptnetflow_ubuntu-20.04-amd64.charm
charmcraft.yaml  README.md             requirements.txt  src
config.yaml      requirements-dev.txt  run_tests         test_charm.py
```

The command `charmcraft pack` combines all configuration files, dependencies and code created for the juju charm in a unique .charm file, which contains all necessary for its deployment.

# Deployment
```shell
# Add a new juju model and deploy the juju charm created
juju add-model model_name
juju deploy ./iptnetflow_ubuntu-20.04-amd64.charm --resource image=lopeez97/iptnetflow:latest

# See the deployment status
juju status
Model        Controller  Cloud/Region        Version  SLA          Timestamp
development  micro       microk8s/localhost  2.9.32   unsupported  09:15:46Z

App         Version                     Status  Scale  Charm       Channel  Rev  Address        Exposed  Message
iptnetflow  lopeez97/iptnetflow:latest  active      1  iptnetflow             0  external_ip    no       

Unit           Workload  Agent  Address      Ports   Message
iptnetflow/0*  active    idle   internal_ip  22/TCP  
```

The implementation of this juju charm is destined to container-based scenarios (K8s). For that, juju has developed the [ops (Charmed Operator Framework) library](https://pypi.org/project/ops/), which simplifies the implementation and lifecycle management of such proxy charms. For instance, it is not necessary to provide the parameters for a ssh-connection between the proxy charm and xNF image, ops performs that connection in a transparent way for the developer.

# Actions
This charm implements different built-in actions to interact with the xNF and the internal services.
```shell
# Execute action and check output
juju run-action iptnetflow/0 start-netflow
juju show-action-output 2
UnitId: iptnetflow/0
id: "2"
results:
  output: 'NetFlow collector started for {ip}:{port} successfully'
status: completed
timing:
  completed: 2022-10-10 09:28:04 +0000 UTC
  enqueued: 2022-10-10 09:27:54 +0000 UTC
  started: 2022-10-10 09:27:57 +0000 UTC
```

To see the list of available actions, check the `actions.yaml` file.

## Action coding example
In `src/charm.py`, you can add your custom actions. This example implements the execution of commands into the xNF via the `run` action.

```python
...
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, BlockedStatus

...
    def __init__(self, *args):
        """Initialize charm and configure states and events to observe."""
        super().__init__(*args)

        self.framework.observe(self.on.run_action, self._on_run_action)

    def _on_run_action(self, event):
        """Execute command receiving the command as input"""
        cmd = event.params["cmd"]
        try:
            os.system(cmd)

            event.set_results({
                "output": f"Command: {cmd} executed successfully"
            })
        except Exception as e:
            event.fail(f"Command: {cmd} failed with the following exception: {e}")
```

# Contact information
PALANTIR Homepage: https://www.palantir-project.eu/
