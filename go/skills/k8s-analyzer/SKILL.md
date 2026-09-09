---
name: k8s-analyzer
description: Kubernetes(K8s)集群核心组件故障自动化分析技能，支持kube-apiserver、etcd、kubelet、containerd、CNI(Calico/Cilium)、CoreDNS、CSI存储、Controller Manager、Scheduler等核心组件日志分析，覆盖节点NotReady、Pod调度失败、服务访问异常、etcd集群异常、网络不通、存储挂载失败等高频K8s故障场景，自动过滤非致命告警、匹配错误特征、定位根因并给出修复建议，支持GB级大日志文件流式处理。当用户提到"K8s故障"、"Kubernetes集群异常"、"Pod启动失败"、"节点NotReady"、"kubelet报错"、"etcd故障"、"CNI网络异常"、"CoreDNS解析失败"、"PV挂载失败"、"K8s日志分析"时使用本技能。
---

# K8s集群核心组件故障分析技能
## 适用场景
Kubernetes集群全栈核心组件故障排查，覆盖：
1. **控制平面组件**：kube-apiserver、etcd、kube-controller-manager、kube-scheduler
2. **节点组件**：kubelet、containerd/Docker、kube-proxy
3. **网络组件**：Calico、Cilium、Flannel、CoreDNS
4. **存储组件**：各类CSI存储驱动、PV/PVC挂载异常
5. **通用集群故障**：节点NotReady、Pod CrashLoopBackOff/ImagePullBackOff、调度失败、服务访问不通、DNS解析失败

## 前置准备
### 1. 日志采集要求
需提供以下组件日志（可提供单个或多个，支持压缩包）：
- 控制平面：`/var/log/kube-apiserver.log`、`/var/log/etcd/etcd.log`、`/var/log/kube-controller-manager.log`、`/var/log/kube-scheduler.log`
- 节点侧：`/var/log/kubelet.log`、`/var/log/containerd.log`（或docker.log）、`/var/log/kube-proxy.log`
- 网络组件：Calico(`/var/log/calico/`)、Cilium(`/var/log/cilium/`)、CoreDNS(`kubectl logs -n kube-system coredns-xxx`)
- 存储组件：CSI插件日志、`kubelet.log`中挂载相关日志
- 集群事件：`kubectl get events --sort-by='.lastTimestamp'`输出
- 节点状态：`kubectl get nodes -o wide`、`kubectl describe node <node-name>`输出

### 2. 工具依赖
- Python 3.6+（无需额外依赖，标准库即可运行）
- 可选：kubectl（用于采集集群状态信息）

---

## 分析流程
### 第一步：日志预处理
使用配套预处理脚本自动解析所有K8s日志，提取关键错误：
```bash
python3 scripts/k8s_log_preprocess.py <log_path_or_directory> [output_report.md]
```
脚本特性：
- 支持单日志文件、目录递归扫描、.tar/.gz/.zip压缩包自动解压
- 流式处理大文件，支持GB级日志无内存压力
- 自动识别组件类型，过滤INFO/DEBUG级非关键日志
- 匹配内置K8s错误关键字特征库，按组件分类错误
- 自动关联错误时间线，定位第一个致命错误
- 自动识别误报和已知非致命告警
- 输出结构化Markdown诊断报告

### 第二步：核心组件故障判定（按优先级）
#### 1. etcd（最高优先级，集群大脑）
etcd故障会导致整个集群控制面不可用，优先排查：
- 集群健康状态：`etcdctl endpoint health`
- 常见错误：leader选举频繁、WAL日志损坏、磁盘IO超时、成员列表不一致、空间配额不足
- 关键报错关键字：`leader changed`、`mvcc: database space exceeded`、`wal: sync duration`、`request timed out`、`etcdserver: too many requests`

#### 2. kube-apiserver（控制面入口）
常见错误：
- 证书过期/配置错误：`x509: certificate has expired`、`connection refused`
- 限流/负载过高：`apiserver is overloaded`、`Too many requests`、`context deadline exceeded`
- etcd连接失败：`etcdclient: failed to connect`、`etcdserver: request timed out`
- 准入Webhook失败：`failed calling webhook`、`webhook returned status 500`
- RBAC权限拒绝：`forbidden: User "xxx" cannot`

#### 3. kubelet（节点代理）
常见错误：
- 节点NotReady：`failed to get node`、`node not found`、`PLEG is not healthy`
- 证书过期：`x509: certificate has expired`、`failed to rotate certificate`
- 容器运行时连接失败：`failed to connect to containerd`、`docker daemon is not running`
- 镜像拉取失败：`ImagePullBackOff`、`ErrImagePull`、`manifest unknown`、`unauthorized`
- 磁盘压力：`DiskPressure`、`NodeHasDiskPressure`、`eviction manager`
- PLEG异常：`PLEG is not healthy`是节点卡死的典型特征

#### 4. 容器运行时（containerd/Docker）
常见错误：
- 镜像拉取失败：`failed to pull image`、`connection refused`、`TLS handshake timeout`
- 容器启动失败：`failed to create container`、`oci runtime error`、`runc create failed`
- 存储驱动异常：`failed to mount overlay`、`no space left on device`
- CNI网络插件调用失败：`failed to setup network for sandbox`

#### 5. CNI网络组件（Calico/Cilium）
常见错误：
- 路由/BGP会话异常：`BGP session not established`、`failed to create route`
- IPAM地址耗尽：`no addresses available in range`、`IPAM allocation failed`
- 网络策略拦截：`denied by policy`、`connection reset by policy`
- Pod网络不通：`failed to create veth pair`、`interface not found`
- eBPF程序加载失败（Cilium）：`failed to load bpf program`、`verifier error`

#### 6. CoreDNS
常见错误：
- 解析超时：`i/o timeout`、`SERVFAIL`、`connection refused`
- 上游DNS异常：`failed to connect to upstream`、`forward plugin error`
- 循环解析：`loop detected`
- CoreDNS Pod异常：CrashLoopBackOff、 readiness probe失败

#### 7. CSI存储组件
常见错误：
- PV挂载失败：`failed to mount volume`、`MountVolume.SetUp failed`、`attachment timeout`
- 存储权限错误：`permission denied`、`invalid credentials`
- 存储连通性失败：`connection refused`、`i/o timeout`
- 扩容失败：`volume expansion failed`、`resize not supported`

#### 8. Controller Manager & Scheduler
常见错误：
- 控制器同步失败：`failed to sync`、`reconciler error`
- 调度失败：`0/xxx nodes are available`、`Insufficient cpu/memory`、`node(s) had taint`、`node affinity/selector mismatch`
- 副本集异常：`failed to create pod`、`back-off restarting failed container`

---

## 非致命误报过滤规则
以下报错属于正常现象或已知非致命错误，自动忽略不纳入根因：
1. `TLS handshake error from ... EOF`：探针/健康检查产生的正常断开连接
2. `failed to read from watch channel ... connection reset`：API Server和etcd之间的watch正常重连
3. `use of closed network connection`：组件重启时的正常连接断开
4. `context canceled`：请求正常取消
5. `object has been modified`：K8s乐观锁冲突，自动重试即可
6. `node xxx not found`：节点/Pod创建删除过程中的临时状态
7. `no endpoints available for service`：服务启动过程中的临时状态
8. Calico/Cilium中已知的feature not supported告警，不影响功能
9. kubelet定期同步时的短暂连接超时，自动恢复的无需关注

---

## 诊断输出模板
```markdown
# 📌 K8s集群故障诊断报告
### 1. 问题概览
- 集群信息：K8s版本、节点数量、故障影响范围
- 故障现象：组件异常类型、影响范围、故障起始时间
- 异常组件：识别到的异常核心组件列表

### 2. 关键证据
1. 故障时间线：按时间排序的关键错误事件
2. 组件错误统计：各组件ERROR/FATAL级错误数量
3. 根因错误点：第一个触发故障的致命错误位置（组件+日志行号+报错内容）
4. 关联错误：根因引发的连锁报错列表

### 3. 根因诊断
明确根因分类（etcd故障/证书过期/网络异常/存储故障/资源不足/配置错误等），给出具体错误点和影响链路。

### 4. 修复建议
按优先级给出可落地修复步骤，包含具体命令、配置修改示例，以及验证方法。
```

## 注意事项
1. **etcd优先原则**：任何集群级故障优先排查etcd健康状态，etcd故障会引发所有其他组件连锁报错
2. **时间线原则**：故障根因一定是第一个出现的ERROR级错误，后续错误大概率是连锁反应
3. **PLEG is not healthy**：出现该错误时90%概率是节点上containerd/docker卡死或磁盘IO耗尽，导致kubelet无法获取容器状态
4. **证书错误**：集群大面积异常时优先检查组件证书是否过期，`kubeadm certs check-expiration`可快速验证
5. **资源不足**：调度失败、Pod被驱逐优先检查节点CPU/内存/磁盘资源是否充足，`kubectl top nodes`验证
6. **网络故障**：Pod之间不通优先检查CNI组件状态、网络策略、Service/Endpoint是否正常
7. **压缩日志支持**：脚本自动处理.tar/.gz/.zip格式的日志包，无需手动解压
