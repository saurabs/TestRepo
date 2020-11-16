.. _repair:


.. contents::
   :depth: 2

================
Repair Bootstrap
================

In case of problem with the bootstrap the following command can be used:

 .. sourcecode:: bash

    $ sudo mdt init

 The following actions are done:

  ==================================================== ==============
  Component                                                Action
  ==================================================== ==============
  Docker                                               restart
  Mdt and helm repo                                    restart httpd
  Containers packages are reloaded if new or different
  Containers used on mdt bootstrap                     recreate
  ==================================================== ==============

======================
Repair MDT containers
======================

In case of problem with MDT containers, as connection problems with mongo or rabbitmq:

 .. sourcecode:: bash

    $ docker logs mdt-api-kube
    INFO:mdt_kube:Using default logging configuration.
    INFO:ericsson.mdt.kube.main:Application configuration from environment variables
    INFO:ericsson.mdt.kube.main:Configuration: {'server': {'host': '0.0.0.0', 'port': '8061'}, 'storage': {'name': 'mediakind', 'host': 'mongo', 'port': '27017'}, 'logger': {'host': 'localhost', 'port': '9030'}}
    WARNING:ericsson.mdt.kube.mongo:Failed to connect to mongodb, retry in 1 second
    …

    $ docker logs mdt-api-products
    timed out
    Messaging Server Connection error on [rabbitmq]
    Messaging Server Connection error on [rabbitmq]
    …

You can stop and run again the containers:

 .. sourcecode:: bash


    $ cd /opt/mfvp/deploypattern/compose
    $ sudo docker-compose -f compose_mdt.yaml down
    $ sudo docker-compose -f compose_mdt.yaml up -d

In case you can't access MDT ui because ``Proxy error: DNS lookup failure``
Try to restart docker compose with mdt init command

 .. sourcecode:: bash

    $ sudo mdt init

.. _repairkubecluster:

===================
Repair Kube Cluster
===================

Deploy operation
================

This part lists some errors that can occur during the Kube deployment and how to fix them.

Scale operation instead of deploy cluster
-----------------------------------------

If MDT realises a scale operation instead of deployment, check that the folder */artifacts* is removed and run again the command.
This case arrives when previous reset kube cluster command is not finished correctly and this folder is not removed.

Calling get operation for cfg resource
----------------------------------------

.. sourcecode:: bash

    Deploying Kube cluster failed: mdt-cli command failed: 2019-01-30 17:25:03,369 - ericsson.mdt.cli.commands.cfg - ERROR - cfg -Failed to get bundle configurations: HTTPConnectionPool(host='mdt-api-products', port=8060): Max retries exceeded with url: /ai/mdt/products (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7fc110bef0f0>: Failed to establis a new connection: [Errno 111] Connection refused',))

MDT bootstrap containers are not ready, run again the command.

Deploying pattern failed: too many values to unpack
----------------------------------------------------

This can occur at the beginning of a deploy Kube cluster.
MDT can not build the inventory from the matrix, because it can not get the IP addresses of nodes.
Update the ``/etc/hosts`` file with the IP address and hostname, even for an allinone case.


.. sourcecode:: bash

   10.86.71.23      mdt1

TASK [Gathering Facts]
----------------------

.. sourcecode:: bash

    fatal: [localhost]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh:..


Check that SSH keys are well configured with the user used in mdt init command :ref:`initialisation`



TASK [sslcert : copy openssl conf file to create certificate]
-------------------------------------------------------------

.. sourcecode:: bash

    fatal: [allinone-207]: FAILED! => {"changed": false, "failed": true, "msg": "AnsibleUndefinedVariable: 'dict object' has no
    attribute 'address'"}**"ansible_default_ipv4"**: {},

This issue comes from missing address parameter in ansible dict for **ansible_default_ipv4**

The error may come from the missing default gateway on the system.

You can check it:

.. sourcecode:: bash

    $ ip route
    $ default via <IP_address> dev <interface_name>

default route must be present. Otherwise add a default route

.. sourcecode:: bash

    $ sudo ip route add  default via <IP_address> dev <interface_name>


TASK [kubernetes/preinstall : Update package management cache (YUM)]
--------------------------------------------------------------------

Try to clean yum caches and deploy again the Kube cluster

.. sourcecode:: bash

    $ sudo yum clean all
    $ sudo rm -rf /var/cache/yum
    $ sudo mdt deploy kube-cluster

or if error is ``The following packages have pending transactions: ...``

.. sourcecode:: bash

    $ sudo yum-complete-transaction --cleanup-only


TASK [kubernetes/preinstall : Install packages requirements
-----------------------------------------------------------

<<< NEED UI screenshot >>>

|image0|

RPMs are not loaded.
Execute the following command:

.. sourcecode:: bash

    sudo mdt load rpm -f mdt-rpms_kubernetes_1.0.0.003.tgz

TASK [docker : ensure docker packages are installed]
-----------------------------------------------------

The result of this task is ignored (Kubespray playbook), but if it is failed, it means there is a problem with Docker installation.

If there are enabled yum repositories with more recent versions of Docker that MDT wants to install,
Docker is uninstalled by MDT (Kubespray), but it can't be installed again by MDT, because it (Kubespray) uses
specific yum repository configured with local MDT yum repository which is accessible by the MDT bootstrap container http, which is no more running.

To fix this, disable yum repository with more recent Docker version and reinstall, init, and deploy again Kube clluster:

.. sourcecode:: bash

    $ sudo mv /etc/yum.repos.d/<repo_file> /etc/yum.repos.d/<repo_file>_bk
    $ sudo yum clean all
    $ sudo rm -rf /var/cache/yum
    $ sudo cd <Eri...>
    $ sudo ./install.sh
    $ sudo cp <mdt-container_3rd...> /opt/mfvp/deploypattern/resources/
    $ sudo mdt init -i <ip_address> ...
    $ sudo mdt deploy kube-cluster


.. |image0| image:: ../../images/error0.png


TASK [install-k8s-addon-ha : check kubernetes nodes]
----------------------------------------------------

The installation stops at this step.

.. sourcecode:: bash

    fatal: [k8s_3 -> 10.1.15.167]: FAILED! => {"attempts": 20, "changed": true, "cmd": "kubectl get nodes | grep -v \"^NAME\" |
     wc -l", "delta": "0:00:00.189676", "end": "2017-11-01 18:39:58.503218", "failed": true, "rc": 0, "start": "2017-11-01 18:39:58.313542",
     "stderr": "The connection to the server localhost:8080 was refused - did you specify the right host or port?",
     "stderr_lines": ["**The connection to the server localhost:8080 was refused - did you specify the right host or port?**"],
     "stdout": "0", "stdout_lines": ["0"]}

The user cannot get kubectl command

.. sourcecode:: bash

    $ sudo kubectl -n kube-system get po
    $ The connection to the server localhost:8080 was refused - did you specify the right host or port?

Verify the service kubelet is started and running
*************************************************

.. sourcecode:: bash

    $ sudo systemctl status kubelet -l

Verify the manifest files are present in masters
*************************************************

Those files are mandatory to have a proper start of kubernetes.

.. sourcecode:: bash

    /etc/kubernetes/

    ├── x.x.x.x-openssl.conf
    ├── x.x.x.y-openssl.conf
    ├── addons
    │   ├── dashboard
    │   │   └── dashboard.yml
    │   ├── dns
    │   │   ├── coredns-clusterrolebinding.yml
    │   │   ├── coredns-clusterrole.yml
    │   │   ├── coredns-config.yml
    │   │   ├── coredns-deployment.yml
    │   │   ├── coredns-sa.yml
    │   │   ├── coredns-svc.yml
    │   │   ├── dns-autoscaler-clusterrolebinding.yml
    │   │   ├── dns-autoscaler-clusterrole.yml
    │   │   ├── dns-autoscaler-sa.yml
    │   │   └── dns-autoscaler.yml
    │   ├── flannel
    │   │   ├── cni-flannel-rbac.yml
    │   │   └── cni-flannel.yml
    │   └── tiller
    │       └── tiller.yaml
    ├── admin.conf
    ├── kube-controller-manager-kubeconfig.yaml
    ├── kubelet.env
    ├── kube-proxy-kubeconfig.yaml
    ├── kube-scheduler-kubeconfig.yaml
    ├── manifests
    │   ├── kube-apiserver.manifest
    │   ├── kube-controller-manager.manifest
    │   ├── kube-proxy.manifest
    │   └── kube-scheduler.manifest
    ├── node-crb.yml
    ├── node-kubeconfig.yaml
    ├── openssl-master.conf
    ├── ssl
    │   ├── admin-x.x.x.y-key.pem
    │   ├── admin-x.x.x.y.pem
    │   ├── apiserver-key.pem
    │   ├── apiserver.pem
    │   ├── ca-key.pem
    │   ├── ca.pem
    │   ├── front-proxy-ca-key.pem
    │   ├── front-proxy-ca.pem
    │   ├── front-proxy-client-key.pem
    │   ├── front-proxy-client.pem
    │   ├── helm
    │   │   ├── extfile.cnf
    │   │   ├── helm.cert.pem
    │   │   ├── helm.csr.pem
    │   │   └── helm.key.pem
    │   ├── kube-controller-manager-key.pem
    │   ├── kube-controller-manager.pem
    │   ├── kube-proxy-x.x.x.x-key.pem
    │   ├── kube-proxy-x.x.x.x.pem
    │   ├── kube-scheduler-key.pem
    │   ├── kube-scheduler.pem
    │   ├── node-x.x.x.x-key.pem
    │   ├── node-x.x.x.x.pem
    │   ├── service-account-key.pem
    │   └── tiller
    │       ├── ca.crt
    │       ├── ca.key.pem
    │       ├── ca.srl
    │       ├── tiller.csr.pem
    │       ├── tls.crt
    │       └── tls.key
    ├── tokens
    │   ├── known_tokens.csv
    │   ├── system:kubectl-x.x.x.y.token
    │   ├── system:kubelet-x.x.x.x.token
    └── users
        └── known_users.csv

Try to restart manually docker and kubelet
******************************************

.. sourcecode:: bash


    $ sudo systemctl stop kubelet
    $ sudo systemctl restart docker
    $ sudo systemctl start kubelet

At the end, docker and kubelet services must be in state started and running.

Verify SELinux is off
***********************

Verify SELinux is disabled

.. sourcecode:: bash

    $ sudo setenforce 0
    $ sudo sed -i "s/SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
    $ sudo systemctl stop NetworkManager.service
    $ sudo systemctl disable NetworkManager.service

Change the log level to see more traces
***************************************

You may now see some errors in logs like the following:
TODO

Identify the component in error
********************************

The following containers are automatically started in Docker at startup of the server.
Even if removed manually, docker or kubelet will recreate them.

- etcd containers are created by Docker and always restart due to configuration of the bound service etcd (which run the container)

- The pods present in manifests are mandatory to run properly the cluster orchestration. They are static pods and are automatically restarted by kubelet service.

- The items present in addons are mandatory to run properly the cloud video processing deployment.

Note::

    The addons are not present during installation at first start of Kubernetes, they are deploy only after it,
    so it can be normal if you don’t see them.


+----------------------------------------+-------------+-----------------------+
| **Kubernetes component**               | **nodes**   | **type**              |
+========================================+=============+=======================+
| etcd                                   | Masters     | Docker                |
+----------------------------------------+-------------+-----------------------+
| kube-apiserver                         | Masters     | Manifests             |
+----------------------------------------+-------------+-----------------------+
| kube-controller-manager                | Masters     | Manifests             |
+----------------------------------------+-------------+-----------------------+
| kube-scheduler                         | Masters     | Manifests             |
+----------------------------------------+-------------+-----------------------+
| kube-apiserver                         | Masters     | Manifests             |
+----------------------------------------+-------------+-----------------------+
| kube-proxy                             | All         | Manifests             |
+----------------------------------------+-------------+-----------------------+
| nginx-proxy                            | Nodes       | Manifest              |
+----------------------------------------+-------------+-----------------------+
| kube-flannel                           | All         | Addons                |
+----------------------------------------+-------------+-----------------------+
| core-dns                               | Masters     | Addons                |
+----------------------------------------+-------------+-----------------------+
| registry                               | Masters     | Addons                |
+----------------------------------------+-------------+-----------------------+
| kubernetes-dashboard                   | Masters     | Addons                |
+----------------------------------------+-------------+-----------------------+
| tiller-deploy                          | Masters     | Addons                |
+----------------------------------------+-------------+-----------------------+

Check the docker image is reachable and correct
************************************************

Check if HA Docker registries are correct:

.. sourcecode:: bash

    $ sudo mdt get container

The images must be present on all masters. If it is not the case, try to reload image archives:

.. sourcecode:: bash

    $ sudo mdt load container -f <image_archive>


Try also a docker pull of one of the Kubernetes containers.

.. sourcecode:: bash

    $ curl -s -k https://<IP_master>:5000/v2/_catalog
    $ curl -s -k https://<IP_master>:5000/v2/<image-name>/tags/list
    $ sudo docker pull <IP_master>:5000/<image_name>:<image_tag>

Look if ports are not already in use
************************************

Look if in your host server, a third-party service is not running and using a port needed by Kubernetes components

.. sourcecode:: bash

    $ ss -luptn

The list of port used by Kubernetes are listed here: §4.4 Cluster Internal ports used by Kubernetes

Try to identify the component in error

Docker container cannot restart
-------------------------------

.. sourcecode:: bash

    $ docker restart f9cd281b68d2
    Error response from daemon: Cannot restart container f9cd281b68d2: cannot join network of a non running container: 8a4092ea2176007842ba0fcc53aad736e44ab3581dd0b51a6284e3544f46e36e

    $ docker restart 8a4092ea2176
    8a4092ea2176

    $ docker restart f9cd281b68d2
    f9cd281b68d2



Delete node operation
=====================

TASK: reset : reset | Restart network
-------------------------------------

If you have this message:

.. sourcecode:: bash

    Unable to start service network: Job for network.service failed because the control process exited with error code. See "systemctl status network.service" and "journalctl -xe


Connect to the node and check the status of the network service, and try to resolve the problem or reboot the node, before run again the command mdt deploy kube-cluster.

=========================
After Products Deployment
=========================

Flannel problem
===============

Verify flannel information
--------------------------

To check the nodes information, on each one, do the following:

- Verify the flannel.1 and cni0 link are in the same subnet (ex: 10.10.x)

- Verify flannel.1 link has only one IP (mask CIDR /32)

.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **1**\.1/24 scope global cni0
    inet 10.10.\ **1**\.0/32 scope global flannel.1


- Verify the consistency with the configuration file on this node

.. sourcecode:: bash

    $ cat /var/run/flannel/subnet.env
    FLANNEL_NETWORK=10.10.0.0/16
    FLANNEL_SUBNET=10.10.\ **1**\.1/24
    FLANNEL_MTU=1450
    FLANNEL_IPMASQ=true

- Check across the cluster if the other nodes don’t use the same subnets. If it is the case, you have an inconsistency and it can generate loss of packets and mis-routing.

This issue can be due to multiple reinstallations. Repair it manually by following the next chapter procedure.

The typical inconsistency you will see can be the following:

    * Network range set mismatch

.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **2**\.1/24 scope global cni0
    inet 10.10.\ **1**\.0/32 scope global flannel.1
    $ cat /var/run/flannel/subnet.env
    FLANNEL_SUBNET=10.10.\ **1**\.1/24

    * Network range affectation mismatch

.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **2**\.1/24 scope global cni0
    inet 10.10.\ **2**\.0/32 scope global flannel.1
    $ cat /var/run/flannel/subnet.env
    FLANNEL_SUBNET=10.10.\ **3**\.1/24

    * Multiple interface declaration

.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **2**\.1/24 scope global cni0
    inet 10.10.\ **2**\.0/32 scope global flannel.1
    inet 10.10.\ **4**\.0/32 scope global flannel.1
    $ cat /var/run/flannel/subnet.env
    FLANNEL_SUBNET=10.10.\ **2**\.1/24



Repair flannel
--------------

If an inconsistency is detected on flannel in a cluster node, you can try to repair it by following this procedure.

This procedure will restart the flannel networking, which will imply loss of communication and potentially loss of service. It takes less than 5 minutes.

Flannel light repair method
****************************

Step 1 - identify the flannel pod of the faulty node (exec cmd on master)

.. sourcecode:: bash

    $ kubetctl -n kube-system get po -o wide | grep <node_name>
    kube-flannel-ds-20xfl      2/2       Running   3          7d        10.86.77.202   el1-202


Step 2 - On the faulty node directly, delete flannel link

.. sourcecode:: bash

    $ sudo ip link delete flannel.1



Step 3 - delete flannel pod of the faulty node (exec cmd on master):

.. sourcecode:: bash

    $ kubectl -n kube-system delete po kube-flannel-ds-20xfl



Step 4 - After POD auto rebuild, on node:

   *  verify flannel.1 and cni0 IP are on the same subnet (ex: 10.10.x) and flannel IP is unique

.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **1**\.1/24 scope global cni0
    inet 10.10.\ **1**\.0/32 scope global flannel.1



  *  verify the consistency with the configuration file on this node

.. sourcecode:: bash

    $ sudo cat /var/run/flannel/subnet.env
    FLANNEL_NETWORK=10.10.0.0/16
    FLANNEL_SUBNET=10.10.\ **1**\.1/24
    FLANNEL_MTU=1450
    FLANNEL_IPMASQ=true


   *  verify the address in the flannel/cni link are unique across the cluster



If the problem is still present with this procedure, try the next forced repair procedure



Flannel forced repair method
*****************************

Step 1 - on the faulty node, delete flannel link:


.. sourcecode:: bash

    $ sudo ip link delete flannel.1



Step 2 - on the faulty node, delete cni link:

.. sourcecode:: bash

    $ sudo ip link delete cni0



Step 3 - on the faulty node, restart kubelet:

# systemctl restart kubelet



Step 4 - on the faulty node, restart docker:

.. sourcecode:: bash

    $ sudo systemctl restart docker



Step 5 - After services restart, on node:

   *  verify flannel.1 and cni0 IP are on the same subnet (ex: 10.10.x) and flannel IP is unique


.. sourcecode:: bash

    $ ip a | grep 'inet.*flannel.1\|inet.*cni0'
    inet 10.10.\ **1**\.1/24 scope global cni0
    inet 10.10.\ **1**\.0/32 scope global flannel.1



  *  verify the consistency with the configuration file on this node

.. sourcecode:: bash

    # cat /var/run/flannel/subnet.env
    FLANNEL_NETWORK=10.10.0.0/16
    FLANNEL_SUBNET=10.10.\ **1**\.1/24
    FLANNEL_MTU=1450
    FLANNEL_IPMASQ=true



   * verify the address in the flannel/cni link are unique across the cluster



At the end if still error of connection, the complete procedures could be done on all servers on the platform.



pods with MatchNodeSelector status
==================================

If after the products deployment, the pods are in state **MatchNodeSelector**, you can remove them.
A frequent issue is to forget the labelling step of the cluster node.
In that case, the pods are not able to find where to run.

Check pods with MatchNodeSelector status using following command :

.. sourcecode:: bash

      $ kubectl -n mediakind get po -o wide | grep MatchNodeSelector
      pod1   0/2     MatchNodeSelector   0          15h     <none>          172.30.41.13    <none>
      pod2   0/2     MatchNodeSelector   0          15h     <none>          172.30.41.10    <none>

These pods are useless and must be removed. It can appear after node reset or pod restart and is due to a known issue of Kubernetes scheduler.

This is not a serious problem because running pods are created by kubernetes but it's preferable to clean-up the system periodically by removing the pods with MatchNodeSelector status (they will persist in the Kubernetes database, increasing the number of managed objects).

For example:

.. sourcecode:: bash

      $  kubectl -n mediakind get po | grep  MatchNodeSelector | tail -n +1 | cut -f 1 -d " " |  xargs  kubectl -n mediakind delete po


A pod cannot start
===================

A pod cannot start with error **ImagePullBackOff** or **ErrimagePull**.

.. sourcecode:: bash

    $ kubectl -n mfvp get po
    NAME           READY     STATUS             RESTARTS   AGE
    redis    0/1       ImagePullBackOff   0          44s

or

.. sourcecode:: bash

    $ kubectl -n mfvp get po
    NAME           READY     STATUS             RESTARTS   AGE
    mongo-0    0/1       ErrImagePull0          44s

Look the reason into description

.. sourcecode:: bash

    $ kubectl -n mfvp describe po redis
    Failed to pull image "10.10.10.10:5000/redis:1.2.0": Error: image redis:1.2.0 not found

Look at the registry to see the list of available containers:

.. sourcecode:: bash

    $ curl -s -k https://<IP_master>:5000/v2/_catalog
    $ curl -s -k https://<IP_master>:5000/v2/<container-name>/tags/list

If not present, reload it by using MDT upload command.

If present, try to pull it from the starting pod host:

.. sourcecode:: bash

    $ docker pull <IP_master>:5000/redis:1.2.0

A node becomes not ready
========================

Once a node is in mode NotReady, no pod will be started on it but it will keep its old running pods

It can be due to hostname modification

.. sourcecode:: bash

    $ kubectl get no
    NAME                   STATUS     AGE       VERSION
    el1-202                Ready      2d        v1.7.0
    el2-203                Ready      2d        v1.7.0
    mas1-212               Ready      2d        v1.7.0
    mas2-213               Ready      2d        v1.7.0
    mas3-214               NotReady   2d        v1.7.0
    mas3-214.envivio.com   Ready      16m       v1.7.0
    pac1-204               Ready      2d        v1.7.0
    pac2-205               Ready      2d        v1.7.0


In that case, set back the correct hostname to your node, restart kubectl and kill the pods started on the fake node.



========================
Check Helm Charts syntax
========================

If you encounter errors with Helm charts during the deployment of products, you can use the following command to check if charts haven't syntax errors:

.. sourcecode:: bash

    helm lint <chart_dir | chart_tgz>

If the linter encounters things that will cause the chart to fail installation, it will emit [ERROR] messages. If it encounters issues that break with convention or recommendation, it will emit [WARNING] messages.

Command documentation here_.

.. _here: https://github.com/helm/helm/blob/master/docs/helm/helm_lint.md

.. note::

    ``helm lint`` do not detect all syntax errors.


=================
Deploy Products
=================

At the end of products deployment, there are some errors, like below. ::

    - error: 'Helm command ''/usr/local/bin/helm3 upgrade etcd helm_repo/etcd --version
        4.3.8-noscaling -f /helm/charts/values/values_etcd_4.3.8-noscaling.yml --install
        --namespace  dev-deployment  --kubeconfig /tmp/kubernetes/admin.conf --registry-config
        /home/mediakind/.config/helm/registry.json --repository-config /home/mediakind/.config/helm/repositories.yaml''
        returned non-zero exit status 1. Error: b''Error: failed to download "helm_repo/etcd"
        (hint: running **`helm repo update`** may help)\n'''

Check that charts are loaded: ::

    sudo mdt get charts

====================
Firewall
====================

.... IN PROGRESS ....

Docker, Kubernetes and kube-proxy pods are configured to add iptables rules.
Theses rules are useful to configure communications between containers in the same node or in different nodes.
It means that theses rules can interact with the firewall configuration.
The rules are not persistent and they are built when docker or kubelet services restart.

Firewall vs iptables
=====================

iptables uses *tables*, *chains* and *targets*.
Firewall uses *zones* and *services*. Firewall is a frontend iptables.

iptables
========

Tables: *filter*, *nat*, *mangle*, *raw*, *security*

Predefined chains: *PREROUTING*, *POSTROUTING*, *INPUT*, *OUTPUT*, *FORWARD*

Predefined targets: *ACCEPT*, *DROP*, *REJECT*, *RETURN*, *MASQUERADE*


Custom chains: they are similar subroutines, they will be called if predefined chain jump to them,
when custom chain execution is finished, it calls back to calling chain.

Docker rules
-------------

MDT containers are managed by compose with the network *mdt_default*.

To check Docker networks in MDT:

.. sourcecode:: bash

    $ sudo docker network ls
    NETWORK ID          NAME                DRIVER              SCOPE
    8fcfcd7d6502        bridge              bridge              local
    3e5daa49891a        host                host                local
    950409c423f0        mdt_default         bridge              local
    e10a930dc3a7        none                null                local


The network *bridge* is default and it corresponds to virtual bridge interface *docker0* for the host.
The virtual bridge corresponding to network *mdt_default* is *br-950409c423f0* (br-<networkID>).

To check MDT containers in that network:

.. sourcecode:: bash

    $ sudo docker network inspect mdt_default
    [
        {
            "Name": "mdt_default",
            "Id": "0b20fc9292f139e4b1d5fe33d80a1d7615b2912ca88fe33dde184cf9a49c6396",
            "Created": "2020-07-16T15:23:56.176775068Z",
            "Scope": "local",
            "Driver": "bridge",
            "EnableIPv6": false,
            "IPAM": {
                "Driver": "default",
                "Options": null,
                "Config": [
                    {
                        "Subnet": "172.18.0.0/16",
                        "Gateway": "172.18.0.1"
                    }
                ]
            },
            "Internal": false,
            "Attachable": true,
            "Ingress": false,
            "ConfigFrom": {
                "Network": ""
            },
            "ConfigOnly": false,
            "Containers": {
                "4c029b169ed9bf2e77c4580428981978c5e673ca6863d98041d2bb877f7213a1": {
                    "Name": "mdt-api-products",
                    "EndpointID": "ab2b207dfafaa00762b0b23a8b7218e492f039f2fd2899f16ff30aec31684483",
                    "MacAddress": "02:42:ac:12:00:02",
                    "IPv4Address": "172.18.0.2/16",
                    "IPv6Address": ""
    ....


Custom chains added by Docker are :

- **DOCKER**,
- **DOCKER-ISOLATION**, to restrict communication between Docker networks,
- **DOCKER-USER**, the last one to add your own rules.

Tables after MDT installation and initialization:

**nat table**:

Nat table contains the rules responsible for masking IP addresses or ports. Docker uses nat to allow containers
on bridge networks to communicate with destinations outside the docker host.

Rules altering packets before they come into the network stack immediately after being received by an interface ::

    Chain PREROUTING (policy ACCEPT)
    num  target     prot opt source               destination
    1    DOCKER     all  --  0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL

    Chain INPUT (policy ACCEPT)
    num  target     prot opt source               destination

    Chain OUTPUT (policy ACCEPT)
    num  target     prot opt source               destination
    1    DOCKER     all  --  0.0.0.0/0           !127.0.0.0/8          ADDRTYPE match dst-type LOCAL


Rules altering packets before they enter/leave the virtual Docker bridge interface or br-0b20fc9292f1 describes how each source IP in the Docker subnet (e.g. 172.17.X.X) or in the br-0b20fc9292f1 network (e.g. 172.18.X.X) will be targeted as MASQUERADE when sent to any destination IP, which overrides the source IP with the interface IP.

rule 1: all packets coming from docker0 subnet that are not going to be sent via the interface docker0 jump to MASQUERADE which assigns the corresponding IP of the outgoing interface to matching packets ::

    Chain POSTROUTING (policy ACCEPT 42 packets, 2520 bytes)
    num   target     prot opt in     out                source               destination
    1     MASQUERADE  all  --  *      !docker0          172.17.0.0/16        0.0.0.0/0
    2     MASQUERADE  all  --  *      !br-0b20fc9292f1  172.18.0.0/16        0.0.0.0/0
    3     MASQUERADE  tcp  --  *      *                 172.18.0.4           172.18.0.4           tcp dpt:15672
    4     MASQUERADE  tcp  --  *      *                 172.18.0.5           172.18.0.5           tcp dpt:443
    5     MASQUERADE  tcp  --  *      *                 172.18.0.5           172.18.0.5           tcp dpt:80
    6     MASQUERADE  tcp  --  *      *                 172.18.0.9           172.18.0.9           tcp dpt:8000

Rules to update destination according to the port ::

    Chain DOCKER (2 references)
    num   target     prot opt in     out     source               destination
    1     RETURN     all  --  docker0 *       0.0.0.0/0            0.0.0.0/0
    2     RETURN     all  --  br-0b20fc9292f1 *       0.0.0.0/0            0.0.0.0/0
    3     DNAT       tcp  --  !br-0b20fc9292f1 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:32768 to:172.18.0.4:15672
    4     DNAT       tcp  --  !br-0b20fc9292f1 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 to:172.18.0.5:443
    5     DNAT       tcp  --  !br-0b20fc9292f1 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:172.18.0.5:80
    6     DNAT       tcp  --  !br-0b20fc9292f1 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8000 to:172.18.0.9:8000


**filter table**:

Filter is the security rules table used to allow or deny traffic to IP addresses, networks or interfaces.
By default, all containers can communicate with each other and the outside world.

Chain for processing packets arriving at the host and destined for the same host ::

    Chain INPUT (policy ACCEPT)
    num  target     prot opt source               destination

Chain for packets entering the host but with a destination outside the host

- rule 1: call chain DOCKER-USER (user specific rule) like subroutine

- rule 2: call chain DOCKER-ISOLATION-STAGE-1 like subroutine to drop packets between containers which belong to 2 different networks docker0 and br-950409c423f0

- rule 3: accept established and related connections to a container from the outside world or from another container for docker0 network

- rule 4: jump to the DOCKER chain for packets coming to a container from the outside world or from another container for docker0 network

- rule 5: accept packets coming from a container to the outside world for docker0 network

- rule 6: accept packets between containers in the network docker0

- rules 7 to 10: like rules 3 to 6 but for br-0b20fc9292f1 network ::

    Chain FORWARD (policy DROP)
    num   target     prot opt               in          out             source               destination
    1     **DOCKER-USER**  all  --              *           *               0.0.0.0/0            0.0.0.0/0
    2     **DOCKER-ISOLATION-STAGE-1**  all  --  *          *               0.0.0.0/0            0.0.0.0/0
    3     ACCEPT     all  --                *           docker0         0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    4     **DOCKER**     all  --                *           docker0         0.0.0.0/0            0.0.0.0/0
    5     ACCEPT     all  --                docker0     !docker0        0.0.0.0/0            0.0.0.0/0
    6     ACCEPT     all  --                docker0     docker0         0.0.0.0/0            0.0.0.0/0
    7     ACCEPT     all  --                *           br-0b20fc9292f1  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    8     **DOCKER**     all  --                *           br-0b20fc9292f1  0.0.0.0/0            0.0.0.0/0
    9     ACCEPT     all  --                br-0b20fc9292f1 !br-0b20fc9292f1  0.0.0.0/0            0.0.0.0/0
    10    ACCEPT     all  --                br-0b20fc9292f1 br-0b20fc9292f1  0.0.0.0/0            0.0.0.0/0

Chain for packets originating on the host to an outside destination ::

    Chain OUTPUT (policy ACCEPT)
    num   target     prot opt in     out     source               destination

Accept only outside packets for mdt containers with specific ports

172.18.0.9:8000 mdt-ui

72.18.0.5:[80|443] httpd

172.18.0.4:15672 rabbitmq ::

    Chain DOCKER (2 references)
    num   target    prot opt    in              out             source               destination
    1     ACCEPT     tcp  --  !br-0b20fc9292f1 br-0b20fc9292f1  0.0.0.0/0            172.18.0.4           tcp dpt:15672
    2     ACCEPT     tcp  --  !br-0b20fc9292f1 br-0b20fc9292f1  0.0.0.0/0            172.18.0.5           tcp dpt:443
    3     ACCEPT     tcp  --  !br-0b20fc9292f1 br-0b20fc9292f1  0.0.0.0/0            172.18.0.5           tcp dpt:80
    4     ACCEPT     tcp  --  !br-0b20fc9292f1 br-0b20fc9292f1  0.0.0.0/0            172.18.0.9           tcp dpt:8000

Custom chain DOCKER-ISOLATION to restrict access between containers managed
by Docker (virtual bridge docker0) and those managed by Docker compose (virtual bridge br-0b20fc9292f1)::

    Chain DOCKER-ISOLATION-STAGE-1 (1 references)
    num   target                    prot opt in                 out             source               destination
    1     DOCKER-ISOLATION-STAGE-2  all  --  docker0            !docker0        0.0.0.0/0            0.0.0.0/0
    2     DOCKER-ISOLATION-STAGE-2  all  --  br-0b20fc9292f1    !br-0b20fc9292f1  0.0.0.0/0            0.0.0.0/0
    3     RETURN                    all  --   *                 *               0.0.0.0/0            0.0.0.0/0

    Chain DOCKER-ISOLATION-STAGE-2 (2 references)
    num   target     prot opt in     out                source               destination
    1     DROP       all  --  *      docker0            0.0.0.0/0            0.0.0.0/0
    2     DROP       all  --  *      br-0b20fc9292f1    0.0.0.0/0            0.0.0.0/0
    3     RETURN     all  --  *      *                  0.0.0.0/0            0.0.0.0/0

Custom chain to add specific rules ::

    Chain DOCKER-USER (1 references)
    num   target     prot opt in     out     source               destination
    1     RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0



Kubernetes rules
----------------

Kubernetes networking uses iptables to control the network connections between pods (and between nodes),
handling many of the networking and port forwarding rules.

All kubernetes packets are marked 0x4000 or 0x8000 (drop packet).

Kube proxy to manage services uses iptables (parameter *proxy_mode*).
It creates a custom chain per service *KUBE-SVC-<service>*, rules under KUBE-SERVICES.
For each *KUBE-SVC-<service>*, it creates one custom chain per pod link to the service *KUBE-SEP-<>*
(SEP for Service End Point) with load balancing.
When traffic is directed to the service ClusterIP, the traffic will use Destination NAT (DNAT)
to change the destination IP address from the ClusterIP to the backend pod IP address.

When traffic is sent from a pod to an external device, the pod IP Address in the source field is changed
(Source NAT) to the nodes external IP address which is routable in the upstream network.

For node port service, Kubernetes has configured IPTables rules to translate the traffic from node IP
address/NodePort to destination pod IP address/port (case kube dashboard).


iptables after Kube deployment:

In the Kube cluster, there are:

- host port service: HA Docker registry

- node port service: Kube dashboard

- 2 services, kubeapi server and coredns.

For visibility, we remove rules for coredns.

**nat table**

Custom chains:

- **CNI-HOSTPORT-DNAT**,

- **CNI-HOSTPORT-SNAT**,

- **KUBE-SERVICES**,

- **KUBE-POSTROUTING**

.. sourcecode:: bash


    Chain PREROUTING (policy ACCEPT 35 packets, 1640 bytes)
    num   target                prot opt in     out     source               destination
    1     CNI-HOSTPORT-DNAT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL
    2     KUBE-SERVICES         all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service portals */
    3     DOCKER                all  --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL

    Chain INPUT (policy ACCEPT 12 packets, 720 bytes)
    num   target     prot opt in     out     source               destination

    Chain OUTPUT (policy ACCEPT 31 packets, 1860 bytes)
    num   target                prot opt in     out     source               destination
    1     CNI-HOSTPORT-DNAT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL
    2     KUBE-SERVICES         all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service portals */
    3     DOCKER                all  --  *      *       0.0.0.0/0           !127.0.0.0/8          ADDRTYPE match dst-type LOCAL

    ## SNAT for all packets with from flannel interface
    Chain POSTROUTING (policy ACCEPT 31 packets, 1860 bytes)
    num   target                prot opt in     out     source               destination
    1     CNI-HOSTPORT-SNAT     all  --  *      *       127.0.0.1           !127.0.0.1
    2     KUBE-POSTROUTING      all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes postrouting rules */
    3     *MASQUERADE Docker...*
    5     RETURN                all  --  *      *       10.234.0.0/16        10.234.0.0/16
    6     MASQUERADE            all  --  *      *       10.234.0.0/16       !224.0.0.0/4
    7     RETURN                all  --  *      *      !10.234.0.0/16        10.234.0.0/24
    8     MASQUERADE            all  --  *      *      !10.234.0.0/16        10.234.0.0/16
    9     *Docker rules...*

    Chain CNI-DN-1068a219b03413ef0d7eb (1 references)
    num   target     prot opt in     out     source               destination
    1     DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000 to:10.234.0.11:5000

    Chain CNI-HOSTPORT-DNAT (2 references)
    num   target                        prot opt in     out     source               destination
    1     CNI-DN-1068a219b03413ef0d7eb  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* dnat name: "cni0" id: "34c524356b4696284e0dc53121e1c68e26d62c6833fc6adb79cf14a8a24916c5" */

    Chain CNI-HOSTPORT-SNAT (1 references)
    num   target                        prot opt in     out     source               destination
    1     CNI-SN-1068a219b03413ef0d7eb  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* snat name: "cni0" id: "34c524356b4696284e0dc53121e1c68e26d62c6833fc6adb79cf14a8a24916c5" */

    Chain CNI-SN-1068a219b03413ef0d7eb (1 references)
    num   target     prot opt in     out     source               destination
    1     MASQUERADE  tcp  --  *      *       127.0.0.1            10.234.0.11          tcp dpt:5000

    Chain KUBE-MARK-DROP (0 references)
    num   target     prot opt in     out     source               destination
    1     MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK or 0x8000

    Chain KUBE-MARK-MASQ (25 references)
    num   target     prot opt in     out     source               destination
    1     MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            MARK or 0x4000

    Chain KUBE-NODEPORTS (1 references)
    num   target                        prot opt in     out     source               destination
    1     KUBE-MARK-MASQ                tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kubernetes-dashboard: */ tcp dpt:30000
    2     KUBE-SVC-XGLOHA7QRQ3V22RZ     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/kubernetes-dashboard: */ tcp dpt:30000

    Chain KUBE-POSTROUTING (1 references)
    num   target     prot opt in     out     source               destination
    1     MASQUERADE  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service traffic requiring SNAT */ mark match 0x4000/0x4000

    Chain KUBE-SEP-24RUYPYQX2E6F4FY (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.3.3           0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.3.3:5000

    Chain KUBE-SEP-2WPEUXA7OMB6FUQL (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.3.4           0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.3.4:8443

    Chain KUBE-SEP-5LT6OPRUIC5E7CRY (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.2.4           0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.2.4:8443

    Chain KUBE-SEP-6443KMROSVC3RO6A (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       192.171.40.33        0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:192.171.40.33:6443

    Chain KUBE-SEP-CSMEFX2GAXLT7FZP (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       192.171.40.31        0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:192.171.40.31:6443

    Chain KUBE-SEP-H4XJ3TI4NXPNG6XG (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.0.8           0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.0.8:8443


    Chain KUBE-SEP-KIH6FUH3MIHL2S7U (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       192.171.40.28        0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:192.171.40.28:6443

    Chain KUBE-SEP-VNENQ443DRETZE5G (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.0.11          0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.0.11:5000

    Chain KUBE-SEP-ZD6SRQ4CQHLJPRSL (1 references)
    num   target            prot opt in     out     source               destination
    1     KUBE-MARK-MASQ    all  --  *      *       10.234.2.3           0.0.0.0/0
    2     DNAT              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp to:10.234.2.3:5000

    Chain KUBE-SERVICES (2 references)
    num   target                        prot opt in     out     source               destination
    5     KUBE-MARK-MASQ                tcp  --  *      *      !10.234.0.0/16        10.233.0.2           /* kube-system/docker-registry:docker-registry cluster IP */ tcp dpt:5000
    6     KUBE-SVC-ZAKJNGPLFIWMUF4S     tcp  --  *      *       0.0.0.0/0            10.233.0.2           /* kube-system/docker-registry:docker-registry cluster IP */ tcp dpt:5000
    7     KUBE-MARK-MASQ                tcp  --  *      *      !10.234.0.0/16        10.233.210.138       /* kube-system/kubernetes-dashboard: cluster IP */ tcp dpt:443
    8     KUBE-SVC-XGLOHA7QRQ3V22RZ     tcp  --  *      *       0.0.0.0/0            10.233.210.138       /* kube-system/kubernetes-dashboard: cluster IP */ tcp dpt:443
    9     KUBE-MARK-MASQ                tcp  --  *      *      !10.234.0.0/16        10.233.0.1           /* default/kubernetes:https cluster IP */ tcp dpt:443
    10    KUBE-SVC-NPX46M4PTMTKRN6Y     tcp  --  *      *       0.0.0.0/0            10.233.0.1           /* default/kubernetes:https cluster IP */ tcp dpt:443
    13    KUBE-NODEPORTS                all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL

    Chain KUBE-SVC-NPX46M4PTMTKRN6Y (1 references)
    num   target                    prot opt in     out     source               destination
    1     KUBE-SEP-KIH6FUH3MIHL2S7U  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.33332999982
    2     KUBE-SEP-CSMEFX2GAXLT7FZP  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.50000000000
    3     KUBE-SEP-6443KMROSVC3RO6A  all  --  *      *       0.0.0.0/0            0.0.0.0/0

   Chain KUBE-SVC-XGLOHA7QRQ3V22RZ (2 references)
    num   target                    prot opt in     out     source               destination
    1     KUBE-SEP-H4XJ3TI4NXPNG6XG  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.33332999982
    2     KUBE-SEP-5LT6OPRUIC5E7CRY  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.50000000000
    3     KUBE-SEP-2WPEUXA7OMB6FUQL  all  --  *      *       0.0.0.0/0            0.0.0.0/0

    Chain KUBE-SVC-ZAKJNGPLFIWMUF4S (1 references)
    num   target                    prot opt in     out     source               destination
    1     KUBE-SEP-VNENQ443DRETZE5G  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.33332999982
    2     KUBE-SEP-ZD6SRQ4CQHLJPRSL  all  --  *      *       0.0.0.0/0            0.0.0.0/0            statistic mode random probability 0.50000000000
    3     KUBE-SEP-24RUYPYQX2E6F4FY  all  --  *      *       0.0.0.0/0            0.0.0.0/0

**filter table**

Custom chains:
- **KUBE-SERVICES**,
- **KUBE-EXTERNAL-SERVICES**,
- **KUBE-FIREWALL**,
- **KUBE-FORWARD**,

.. sourcecode:: bash

    Chain INPUT (policy ACCEPT 2302 packets, 518K bytes)
    num   target                        prot opt in     out     source               destination
    1     KUBE-SERVICES                 all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW /* kubernetes service portals */
    2     KUBE-EXTERNAL-SERVICES        all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW /* kubernetes externally-visible service portals */
    3     KUBE-FIREWALL                 all  --  *      *       0.0.0.0/0            0.0.0.0/0

    *## rules 13,14: accept all traffic forward flannel interface*
    Chain FORWARD (policy DROP 0 packets, 0 bytes)
    num   target                        prot opt in     out     source               destination
    1     DOCKER-ISOLATION-STAGE-1      all  --  *      *       0.0.0.0/0            0.0.0.0/0
    2     KUBE-FORWARD                  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes forwarding rules */
    3     KUBE-SERVICES                 all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW /* kubernetes service portals */
    4     *Docker rules*
    13    ACCEPT                        all  --  *      *       10.234.0.0/16        0.0.0.0/0
    14    ACCEPT                        all  --  *      *       0.0.0.0/0            10.234.0.0/16

    Chain OUTPUT (policy ACCEPT 2376 packets, 330K bytes)
    num   target            prot opt in     out     source               destination
    1     KUBE-SERVICES     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW /* kubernetes service portals */
    2     KUBE-FIREWALL     all  --  *      *       0.0.0.0/0            0.0.0.0/0

    Chain KUBE-EXTERNAL-SERVICES (1 references)
    num   target     prot opt in     out     source               destination

    Chain KUBE-FIREWALL (2 references)
    num   target     prot opt in     out     source               destination
    1     DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes firewall for dropping marked packets */ mark match 0x8000/0x8000

    Chain KUBE-FORWARD (1 references)
    num   target     prot opt in     out     source               destination
    1     ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes forwarding rules */ mark match 0x4000/0x4000
    2     ACCEPT     all  --  *      *       10.234.0.0/16        0.0.0.0/0            /* kubernetes forwarding conntrack pod source rule */ ctstate RELATED,ESTABLISHED
    3     ACCEPT     all  --  *      *       0.0.0.0/0            10.234.0.0/16        /* kubernetes forwarding conntrack pod destination rule */ ctstate RELATED,ESTABLISHED

    Chain KUBE-SERVICES (3 references)
    num   target     prot opt in     out     source               destination


Firewall
=========

MDT rules
---------

MDT adds firewall rules before deploy Kube cluster.
Before Kube cluster deployment, the iptables are saved in file */opt/iptables_before_cluster*

On the master nodes
*******************

- MDT opens TCP *kube_apiserver_port* used by Kube apiserver for MDT containers.
- All masters kube containers need to access all etcd containers managed by Docker on other masters, then MDT opens the TCP ports 2379 and 2380.
- If there is a VIP managed by Keepalived, MDT authorizes protocol VRRP.


On all nodes
************

- The kubelet uses the port 10250, MDT opens this port for commands like *kubectl logs* or *kubectl describe* when pods are on remote hosts.
- Flannel is paired with VXLAN backend (recommended). It encapsulates packets and sends them via UDP on port 8472, MDT opens this port.
- The virtal interface *cni0* is set in *trusted* zone.

Debug iptables
==============

To debug issues with iptables/firewall, you can use the target *TRACE* in  *raw* table.
The *raw* table has 2 chains: *PREROUTING* and *OUTPUT*. You must add rules to these chains to capture packets.

Activate trace
---------------

To enable trace, you must enable netfilter log:

.. sourcecode:: bash

    sudo modprobe nf_log_ipv4
    sudo sysctl net.netfilter.nf_log.2=nf_log_ipv4

Example, to debug access to HA Docker registries which use port 5000:

.. sourcecode:: bash

    sudo iptables -t raw -I OUTPUT -p tcp --dport 5000 -j TRACE
    sudo iptables -t raw -I OUTPUT -p tcp --sport 5000 -j TRACE
    sudo iptables -t raw -I PREROUTING -p tcp --dport 5000 -j TRACE
    sudo iptables -t raw -I PREROUTING -p tcp --sport 5000 -j TRACE

.. warning::

    There can be many traces and sometime there is CPU problem and you can't access iptables:
    *Another app is currently holding the xtables lock. Perhaps you want to use the -w option?*
    Try to reduce trace, by remove liveness or readyness probes.
    If you can't do any thing, reboot the node to flush raw table.

Log interpretation
-------------------

The var log file is */var/log/messages*.

You can search iptables log with:

.. sourcecode:: bash

    sudo cat /var/log/messages | grep TRACE

    May 20 13:01:14 firewall-node-1 kernel: TRACE: filter:INPUT:rule:3 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=97 TOS=0x00 PREC=0x00 TTL=64 ID=22693 DF PROTO=TCP SPT=47598 DPT=6443 SEQ=2943779168 ACK=2025033196 WINDOW=8698 RES=0x00 ACK PSH URGP=0 OPT (0101080A0004DB2D0004D35D)
    May 20 13:01:14 firewall-node-1 kernel: TRACE: filter:KUBE-FIREWALL:return:2 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=97 TOS=0x00 PREC=0x00 TTL=64 ID=22693 DF PROTO=TCP SPT=47598 DPT=6443 SEQ=2943779168 ACK=2025033196 WINDOW=8698 RES=0x00 ACK PSH URGP=0 OPT (0101080A0004DB2D0004D35D)
    May 20 13:01:14 firewall-node-1 kernel: TRACE: filter:INPUT:rule:4 IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=97 TOS=0x00 PREC=0x00 TTL=64 ID=22693 DF PROTO=TCP SPT=47598 DPT=6443 SEQ=2943779168 ACK=2025033196 WINDOW=8698 RES=0x00 ACK PSH URGP=0 OPT (0101080A0004DB2D0004D35D)
    ...

You can check specific packet with its ID, and keep only some data:

.. sourcecode:: bash

    sudo cat /var/log/messages | grep ID=22693 | cut -d ' ' -f 8,9.10,12,13

The trace give the table, chain and number rules used, example: *filter:INPUT:rule:4*.
To see corresponding rule, display iptables with rule numbers:

.. sourcecode:: bash

    sudo iptables -t filter -nvL --line-numbers

.. warning::

    Note that the chains in the nat table are NOT traversed by the return packet.
    This is by design; only packets in the "NEW" state go through nat chains.

Packet trace
------------

You can use *tcpdump* or *netsniff-ng*.


Stop tracing
------------

Don't forget to stop trace, when debug session is finished, remove rules.

Example:

.. sourcecode:: bash

    sudo iptables -t raw -D OUTPUT -p tcp --dport 5000 -j TRACE
    sudo iptables -t raw -D OUTPUT -p tcp --sport 5000 -j TRACE
    sudo iptables -t raw -D PREROUTING -p tcp --dport 5000 -j TRACE
    sudo iptables -t raw -D PREROUTING -p tcp --sport 5000 -j TRACE

Configure or clean firewall outside MDT
=======================================

You can configure or clean firewall outside MDT.

To configure:

.. sourcecode:: bash

    USER=$(cat /etc/deploypattern.conf | grep remote_user | cut -d ' ' -f3)
    KEY=$(cat /etc/deploypattern.conf | grep ssh_key | cut -d ' ' -f3)
    # Set keepalived=true or keepalived=false according to parameter in cfg kube/kube-config.yaml
    KEEPALIVED="keepalived=true"
    sudo mdt get inventory -o inventory.ini
    sudo ansible-playbook -i inventory.ini --become --user=${USER} --private-key=${KEY} --extra-vars ${KEEPALIVED} /opt/mfvp/deploypattern/ansible/config_firewall.yaml

To clean:

.. sourcecode:: bash

    USER=$(cat /etc/deploypattern.conf | grep remote_user | cut -d ' ' -f3)
    KEY=$(cat /etc/deploypattern.conf | grep ssh_key | cut -d ' ' -f3)
    # Set keepalived=true or keepalived=false according to parameter in cfg kube/kube-config.yaml
    KEEPALIVED="keepalived=true"
    sudo mdt get inventory -o inventory.ini
    sudo ansible-playbook -i inventory.ini --become --user=${USER} --private-key=${KEY} --extra-vars ${KEEPALIVED} /opt/mfvp/deploypattern/ansible/clean_firewall.yaml


Troubleshooting for firewall
============================

Some issues could be happen, if the firewall is restarted after the kube cluster is deployed.

sudo mdt get images
-------------------

If the firewall has been restarted on fist master, you have this message:

.. sourcecode:: bash

    - registry - list_containers - INFO - Be patient, it takes a little time ...
    - registry - list_containers - INFO - ERROR: There is no HA Docker registry, deploy Kube cluster before get container: local variable 'result' referenced before assignment

If firewall has been restarted on another master, the column for this master is empty.

The solution is to delete the docker registry on the master.

.. sourcecode:: bash

    MASTER=*<master>*
    kubectl -n kube-system delete po $(kubectl -n kube-system get po -o wide | grep registry | grep ${MASTER} | cut -d ' ' -f 1)
    sudo mdt get images


