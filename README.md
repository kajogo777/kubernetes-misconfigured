# Kubernetes Misconfigured

+ some defects might not lead to breaches anymore since they affect specific versions of kubernetes
+ some best practices are not applicable to kubernetes packages as they are applied to the cluster as a whole (outside the control of package authors) -> should be excluded
+ some best practices are not directly related to security of workloads -> should be excluded
+ some best practices are relevant only if specific technologies are used (e.g. argocd, ingress-nginx), hence are not applicable if these technologies are not used -> should be excluded?
+ some best practices are not applied to all types of containers ephemeralContainers, initContainers, and containers

# v1
possible defect | related CVEs | terrascan ([7126c48](https://github.com/tenable/terrascan/commit/7126c48f68f7dc89ae54af0d8a9d4fd7faf76bd7)-28/05/2022) | kubesec ([8c562f3](https://github.com/controlplaneio/kubesec/commit/8c562f31a7a56623c907cdc01755fed2efdf15a6)-29/05/2022) | opa gatekeeper ([d6b0ede](https://github.com/open-policy-agent/gatekeeper-library/commit/d6b0edeee2cfb380539e17b6bdcb5ddae98c9e32)-29/05/2022) | kyverno ([2a98bd4](https://github.com/kyverno/policies/commit/2a98bd48e5eb7eca719f708a08b41089c988537a)-30/05/2022) | trivy ([7a02d66](https://github.com/aquasecurity/defsec/commit/7a02d66787c97f428e4ca14810e3b08f882d135c)-02/06/2022) | checkov 
-|:-:|:-:|:-:|:-:|:-:|:-:|:-:
EndpointSlice contains loopback address (localhost or link-local)|CVE-2021-25737|✅
ExternalName service contains localhost address|||||✅
LoadBalancer or Ingress Service not using selector|CVE-2021-25740|✅
Default ClusterRole `system:aggregate-to-edit` can create/patch/update Endpoints and EndpointSlices|CVE-2021-25740|||✅
ClusterIP Service using externalIPs|CVE-2020-8554|✅
Helm v2 (tiller) is used||✅|||✅|✅
NodePort Service is used||✅||✅|✅
Ingress is not HTTPS only (TLS disabled)||✅||✅
container running with securityContext.allowPrivilegeEscalation set||✅|✅|✅|✅|✅
create volumes of types GlusterFS, Quobyte, StorageFS, ScaleIO with kube-controller-manager: v1.18.0, v1.17.0 - v1.17.4, v1.16.0 - v1.16.8, v1.15.11|CVE-2020-8555|✅
Kubernetes Dashboard is used||✅
container running with securityContext.privileged set||✅|✅|✅|✅|✅
container running with any `kernel.*` system calls allowed (e.g. securityContext.sysctls `*`)||✅
Not blacklisting disallowed system calls||||✅
securityContext.sysctls system calls allowed other than  `kernel.shm_rmid_forced, net.ipv4.ip_local_port_range, net.ipv4.ip_unprivileged_port_start, net.ipv4.tcp_syncookies, net.ipv4.ping_group_range`|||||✅
securityContext.sysctls system calls allowed other than  `kernel.shm_rmid_forced, net.ipv4.ip_local_port_range, net.ipv4.tcp_syncookies, net.ipv4.ping_group_range`||||||✅
container mounting hostPath||✅|||✅|✅
Not whitelisting allowed host paths and permissions for hostPath mounting||||✅|✅
container running with securityContext.runAsNonRoot unset||✅|✅||✅|✅
service account tokens are auto mounted||✅||✅|✅|✅
AppArmor profile not set (e.g. default or custom) via annotations||✅||✅
securityContext.procMount is set to `Unmasked`||✅||✅|✅|✅
securityContext.readOnlyRootFileSystem is unset||✅|✅|✅|✅|✅
Mounting volumes with types other than `configMap, emptyDir, projected, secret, downwardAPI, persistentVolumeClaim`||✅
Mounting volumes with types other than `configMap, emptyDir, projected, secret, downwardAPI, persistentVolumeClaim, csi, ephemeral`|||||✅
Mounting volumes with types `gcePersistentDisk, awsElasticBlockStore, gitRepo, nfs, iscsi, glusterfs, rbd, flexVolume, cinder, cephFS, flocker, fc, azureFile, vsphereVolume, quobyte, azureDisk, portworxVolume, scaleIO, storageos, csi` ||||||✅
Not restricting mountable volume types||||✅
windows containers running with hostProcess set|||||✅
containers sharing host process ID namespace, hostPID is set||✅|✅|✅|✅|✅
containers sharing host IPC namespace, hostIPC is set||✅|✅|✅|✅|✅
containers sharing host network namespace, hostNetwork is set||✅|✅|✅|✅|✅
Not whitelisting specific ports that will be shared with host network||||✅|✅|✅
container running with `NET_RAW` capability in securityContext.capabilities||✅|||✅
secrets are mounted as an environmental variable||✅|||✅
container running with `SYS_ADMIN` capability in securityContext.capabilities||✅|✅|||✅
container running with capabilities other than `NET_BIND_SERVICE`|||||✅
container running with capabilities other than `NET_BIND_SERVICE` and `CAP_CHOWN`|||||✅
Not whitelisting allowed container capabilities||||✅|✅|✅
Not blacklisting disallowed container capabilities||||✅
`securityContext` not used in pod, container, and initContainer||✅
using container image without digest||✅||✅|✅
using container image with latest tag||✅|||✅|✅
docker socket is mounted using hostPath||✅|✅||✅|✅
docker, CRI-O, containerd socket is mounted using hostPath|||||✅
container running with uid or gid <= 0, securityContext.runAsUser, runAsGroup, fsGroup. supplementalGroups <= 0|||||✅
container running with uid or gid <= 0, runAsGroup, fsGroup. supplementalGroups <= 0||||||✅
container running with uid < 1000, securityContext.runAsUser < 1000||✅|||✅
container running with gid < 3000, securityContext.runAsGroup < 3000|||||✅
container running with uid <= 10000, securityContext.runAsUser <= 10000|||✅|||✅
container running with gid <= 10000, securityContext.runAsGroup <= 10000|||✅|||✅
container running with gid < 2000, securityContext.fsGroup < 2000|||||✅
Not limiting securityContext.fsGroup ID range||||✅
Not limiting securityContext.runAsUser ID range||||✅
Not limiting securityContext.runAsGroup ID range||||✅
Not limiting securityContext.supplementalGroups ID range (e.g. kyverno specifies 100-200 or 500-600)||||✅|✅
container running with non-cluster-unique uid in security.runAsUser|||||✅
`alwaysPullImages` admission plugin is not enabled||✅
Not setting `imagePullPolicy` to `Always`|||||✅
resource CPU requests not set||✅|✅|✅|✅|✅
resource CPU limits not set||✅|✅|✅||✅
resource Memory requests not set||✅|✅|✅|✅|✅
resource Memory limits not set||✅|✅|✅|✅|✅
liveness probe not set||✅||✅|✅
readiness probe not set||✅||✅|✅
using default Namespace||✅|||✅
Ingress using custom snippet annotations with ingress-nginx|CVE-2021-25742|✅|||✅
Ingress using `metadata.annotations` with ingress-nginx version <v1.2.0|CVE-2021-25746||||✅
Ingress using any allowed `spec.rules[].http.paths[].path` with ingress-nginx version <v1.2.0|CVE-2021-25745||||✅
Using the default ServiceAccount in RoleBinding or ClusterRoleBinding||✅
Pod running using the default ServiceAccount|||✅
Pod running using the default ServiceAccount are allowed to auto mount token|||||✅
Namespace without `owner` label||✅
AppArmor profile not defined in annotations|||✅
AppArmor profiles set to something other than `runtime/default` or `localhost/*`|||||✅
AppArmor profiles set to something other than `runtime/default`||||||✅
securityContext.seccompProfile.type is not set to default type||✅||||✅
Seccomp profile not defined in annotations|||✅
Seccomp profile not defined in securityContext.seccompProfile.type|||||✅
Seccomp profile set as `unconfined` in annotations|||✅||✅
Seccomp profiles are not whitelisted||||✅
Seccomp profile set to something other than `RuntimeDefault` or `Localhost`|||||✅
Selinux config not set||||✅
Selinux config options are defined and set to insecure values|||||✅|✅
Not dropping all capabilities in securityContext.capabilities|||✅||✅|✅
Not dropping any capabilities in securityContext.capabilities|||✅|||✅
Managing hostAliases in a pod|||✅|||✅
StatefulSet VolumeClaimTemplate access mode is not `ReadWriteOnce`|||✅
StatefulSet VolumeClaimTemplate is not specifying storage requests|||✅
emptyDir VolumeClaims do not specifying ephemeral-storage requests|||||✅
Image repos/prefixes are not whitelisted in cluster||||✅|✅|✅
Service externalIPs are not whitelisted in cluster|CVE-2020-8554|||✅|✅
Ingress with wildcard `*` hostname||||✅|✅
Ingress rule hosts are not unique (kyverno checks uniqueness globally)||||✅|✅
Ingress rule paths are not unique (kyverno checks uniqueness globally)|||||✅
ClusterRoleBinding/RoleBinding with subject `system:anonymous` user or `system:unauthenticated` group||||✅
ServiceAccountName can be updated after resource creation||||✅
PodDisruptionBudgets with maxUnavailable set to 0 or minAvailable the same as the number of replicas (blocks node draining)||||✅
Number of replicas is not limited||||✅
Services do not have unique selectors within a namespace||||✅
Not whitelisting flexVolume drivers||||✅
Not using NetworkPolicies with a default deny all policy for all namespaces|||||✅
Using NetworkPolicies without pod or namespace selectors||||||✅
Not using ResourceQuota and LimitRange to restrict the number of resources that can be claimed in a namespace|||||✅|✅
Using deprecated kubernetes APIs|||||✅
Workloads that use hostPath or emptyDir volumes without `safe-to-evict=true` annotations|||||✅
Not whitelisting allowed annotations|||||✅
Not denying label changes of live resources|||||✅
Not whitelisting `priorityClassName`|||||✅
Velero cross-namespace restore is allowed in protected namespaces `kube-system` and `kube-node-lease`|||||✅
Allowing ephemeral (debug) containers by default|||||✅
Container running with a `VOLUME` statement in their OCI image (if run in ro mode, would still result in write access to the specified location)|||||✅
Allowing very large images to run (& pulled)|||||✅
Allowing stale images to run, with layers created more that 6 months ago|||||✅
ServiceAccounts are allowed to create pods that use other ServiceAccounts|||||✅
Secrets usage is allowed in all namespaces by all pods|||||✅
Pods with very large terminationGracePeriodSeconds|||||✅
Create PersistentVolumeClaims with the `nfs-client` storage class with an empty `nfs.io/storage-path` annotation|||||✅
Not whitelisting source of containers that run as root|||||✅
Allow sysctl settings with `=` or `+` in their values|CVE-2022-0811||||✅
Roles other than `cluster-admin` are allowed to modify node taint|||||✅
Regular users allowed to modify/remove node labels|||||✅
Image source is not the same as image source hard-coded in the manifest's annotation or label `org.opencontainers.image.source`|||||✅
Using ExternalDNS, Service are allowed to have duplicate `external-dns.alpha.kubernetes.io/hostname` annotation|||||✅
Scheduling non-system pods on control plane nodes is allowed, pods tolerant to `node-role.kubernetes.io/master` and `node-role.kubernetes.io/control-plane`|||||✅
Ingress defaultBackend can be set|||||✅
Service with type `LoadBalancer` can be created freely|||||✅
Pods can be created with node selection; nodeSelector and nodeName set|||||✅
Service are allowed to expose any ports, other than range 32000-33000|||||✅
Pods can use any ServiceAccount in a namespace|||||✅
Using images without verifying signatures|||||✅
Workloads created without a PodDisruptionBudget|||||✅
Users allowed to exec into all containers|||||✅
Deploying user pods in `kube-system` namespace||||||✅


# Misconfigurations grouped by resource type

Endpoint/EndpointSlice
+ Endpoint/EndpointSlice contains loopback address (localhost or link-local) -> RD
+ Endpoint/EndpointSlices can be created/patched/updated (by default permissions eg. `system:aggregate-to-edit`) -> RD

Service
+ Service ExternalName contains localhost address -> RD
+ Service not using a selector -> RD
+ Service ClusterIP using externalIPs -> RD
+ Service NodePort used -> 
+ Services do not have unique selectors within a namespace -> RD
+ Service with duplicate `external-dns.alpha.kubernetes.io/hostname` annotation (when using ExternalDNS) -> RD
+ Service with exposed ports other than 32000-33000 -> 

Ingress
+ Ingress not using HTTPS -> RD
+ ==Ingress not using a selector== -> RD
+ ==Ingress ingress-nginx using annotations== -> RD 
	+ custom snippet annotations
	+ using any annotations version < v1.2.0
+ ==Ingress ingres-nginx using using any allowed spec.rules[].http.paths[].path with version <v1.2.0== -> RD
+ Ingress with wildcard `*` hostname -> RD
+ Ingress rule hosts are not unique -> RD
+ Ingress rule paths are not unique -> RD
+ Ingress defaultBackend is set -> RD


RoleBinding/ClusterRoleBinding
+ RoleBinding/ClusterRolebinding referencing the default ServiceAccount -> 
+ RoleBinding/ClusterRoleBinding with subject `system:anonymous` user or `system:unauthenticated` group -> 

Role/ClusterRole
+ Role/ClusterRole other than `cluster-admin` allowed to modify node taint
+ Role/ClusterRole other than `cluster-admin` allowed to modify node labels
+ ==Role/ClusterRole other than `cluster-admin` allowed to create service of type `LoadBalancer`==
+ Role/ClusterRole allow users to exec into all containers

ServiceAccount
+ ServiceAccount automountServiceAccountToken is set -> GP
+ ServiceAccount is allowed to create pods that run with other ServiceAccounts -> GP

StatefulSet
+ StatefulSet VolumeClaimTemplate access mode that is not `ReadWriteOnce`
+ StatefulSet VolumeClaimTemplate that does not specify storage requests

VolumeClaim
+ VolumeClaim with type emptyDir that does not specify ephemeral-storage requests

PersistentVolumeClaims
+ PersistentVolumeClaims with the `nfs-client` storage class with an empty `nfs.io/storage-path` annotation -> DSR

PodDisruptionBudgets
+ PodDisruptionBudgets with maxUnavailable set to 0 -> DSE
+ PodDisruptionBudgets with minAvailable set to number of replicas -> DSE
+ PodDisruptionBudget not created for every workload -> DSE

NetworkPolicy
+ no deny all policy for all namespaces -> RD, MD
+ NetworkPolicy without pod or namespace selectors -> BM

ResourceQuota
+ not used for all namespaces -> DSR

LimitRange
+ not used for all namespaces -> DSR

Pod spec
+ Pod spec with securityContext.allowPrivilegeEscalation set -> GP
+ Pod spec with securityContext.privileged set -> GP
+ Pod spec with securityContext.runAsNonRoot unset -> GP
+ Pod spec with securityContext.readOnlyRootFileSystem unset -> MD
+ Pod spec with securityContext.procMount is set to `Unmasked` -> RD
+ Pod spec with securityContext.windowsOptions.hostProcess set -> GP
+ Pod spec with automountServiceAccountToken is set -> GP
+ Pod spec with hostPID set -> GP
+ Pod spec with hostIPC set -> RD, GP
+ Pod spec with hostAliases set ->  
+ Pod spec with hostNetwork set -> RD, MD, GP
	+ set but trying to limit ports via hostPorts
+ Pod spec with securityContext.capabilities -> GP
	+ adds `NET_RAW` capability
	+ adds `SYS_ADMIN` capability
	+ adds `NET_BIND_SERVICE` capability
	+ adds `CAP_CHOWN` capability
	+ not dropping all capabilities
	+ not dropping any capabilities
	+ 
+ Pod spec with securityContext.sysctls -> GP
	+ containing any
		+  `kernel.*`
	+ containing anything other than
		+ `kernel.shm_rmid_forced`
		+ `net.ipv4.ip_local_port_range`
		+ `net.ipv4.ip_unprivileged_port_start
		+ `net.ipv4.tcp_syncookies
		+ `net.ipv4.ping_group_range
	+ containing anything other than
		+ `kernel.shm_rmid_forced`
		+ `net.ipv4.ip_local_port_range`
		+ `net.ipv4.tcp_syncookies
		+ `net.ipv4.ping_group_range
	+ settings with `=` or `+` in their values
+ Pod spec with volume of type `hostPath` -> RD, MD, GP
	+ least privilege mounting host paths, be specific and limit permissions
	+ mounting the docker socket
	+ mounting docker, CRI-O, containerd sockets
+ Pod spec with volume of type other than ->
	+ containing any
		+ `gcePersistentDisk`
		+ `awsElasticBlockStore`
		+ `gitRepo`
		+ `nfs`
		+ `iscsi`
		+ `glusterfs`
		+ `rbd`
		+ `flexVolume`
		+ `cinder`
		+ `cephFS`
		+ `flocker`
		+ `fc`
		+ `azureFile`
		+ `vsphereVolume`
		+ `quobyte`
		+ `azureDisk`
		+ `portworxVolume`
		+ `scaleIO`
		+ `storageos`
		+ `csi`
	+ containing anything other than
		+ `configMap`
		+ `emptyDir`
		+ `projected`
		+ `secret`
		+ `downwardAPI`
		+ `persistentVolumeClaim`
	+ containing anything other than
		+ `configMap`
		+ `emptyDir`
		+ `projected`
		+ `secret`
		+ `downwardAPI`
		+ `persistentVolumeClaim`
		+ `csi`
		+ `ephemeral
	+ ==not whitelisting CSI o flecVolume drivers==
+ Pod annotation AppArmor profile -> BM
	+ not set
	+ set to something other than `runtime/default`
	+ set to something other than `runtime/default` or `localhost/**`
+ Pod spec with secrets mounted as environmental variables -> RD
+ Pod spec not defining a securityContext -> GP
+ Pod spec referencing a container image without a digest -> DSE, UC
+ Pod spec reference a container image with a latest tag -> DSE, UC
+ Pod spec with securityContext.runAsUser -> GP
	+ with uid = 0
	+ with uid < 1000
	+ with uid < 10000
	+ with non-cluster-unique uid
+ Pod spec with securityContext.runAsGroup , fsGroup, supplementalGroups -> GP
	+ with gid set to 0
	+ with gid < 2000
	+ with gid < 3000
	+ with gid < 10000
	+ with gid other than 100-200 or 500-600
+ Pod spec with `imagePullPolicy` not set to `Always` -> BM
+ Pod spec with resource CPU requests not set -> DSR
+ Pod spec with resource CPU limits not set -> DSE
+ Pod spec with resource Memory requests not set -> DSR
+ Pod spec with resource Memory limits not set -> DSR
+ Pod spec with liveness probe not set -> DSE
+ Pod spec with readiness probe not set -> DSE
+ Pod spec with the default ServiceAccount -> GP
+ Pod spec with securityContext.seccompProfile.type -> BM
	+ not set
	+ not set to `RuntimeDefault`
	+ set to something other than  `RuntimeDefault` or `Localhost`
	+ set as `unconfined`
+ Pod spec with selinux config -> BM
	+ not set
	+ set to insecure values
+ Pod spec with volume of type `hostPath` or `emptyDir` without `safe-to-evict=true` annotation -> DSE
+ Pod annotations are not whitelisted -> GP
+ Pod priorityClassName is not whitelisted -> DSR
+ Pod spec with very large terminationGracePeriodSeconds -> DSR
+ Pod spec image source not matching image source hard-coded in manifest's annotation or label (required users to hard-code image source in annotations or labels) -> UC
+ Pod spec tolerant to  `node-role.kubernetes.io/master` and `node-role.kubernetes.io/control-plane` for non-system pods -> DSE, GP
+ Pod spec with nodeSelector and nodeName -> GP

Misc
+ Using Helm v2 (tiller) -> 
+ Using Kubernetes Dashboard
+ ==Volumes of types ClusterFS, Quobyte, StorageFS, ScaleIO  and kube-controller-manager: v1.18.0, v1.17.0 - v1.17.4, v1.16.0 - v1.16.8, v1.15.11==
+ `alwaysPullImages` admission plugin is not enabled -> BM
+ Using the default namespace
+ Namespace with owner label
+ Image repos/prefixes are not whitelisted -> UC
+ Service externalIPs are not whitelisted -> RD
+ Pod spec ServiceAccountName can be patched after creation -> GP
+ Pod spec ServiceAccountName can be set to any ServiceAccount -> GP
+ Number of pod replicas is not limited -> DSR
+ Using deprecated kubernetes APIs -> 
+ Label changes of live resources are allowed ->
+ Velero cross-namespace restore is allowed in protected namespaces `kube-system` and `kube-node-lease` -> MD, DSE, GP, BM
+ Allowing ephemeral containers by default ->
+ Container images with `VOLUME` statement in OCI image -> MD
+ Container images that are very large are allowed to run -> DSR
+ Container images with layers older than 6 months ago -> 
+ Container images without signature verification -> UC
+ Secrets usage is allowed in all namespaces by all pods -> RD, GP
+ Deploying user pods in `kube-system` namespace -> GP


## References
+ https://github.com/aquasecurity/kube-bench
+ https://www.cisecurity.org/benchmark/kubernetes
+ https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md#cis-kubernetes-benchmark-support
+ https://github.com/tenable/terrascan
+ https://runterrascan.io/docs/policies/k8s/
+ https://github.com/open-policy-agent/gatekeeper-library
+ https://github.com/kyverno/policies
+ checkov bridgecrew policies
+ [why hostPath in ro mode?](https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts)
+ [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## TODO
come up with v2, map each v2 item to a score using the CVE formula
