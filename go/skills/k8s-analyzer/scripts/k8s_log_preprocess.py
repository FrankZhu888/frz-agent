#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
K8s集群核心组件日志预处理脚本
功能：自动识别K8s组件类型，过滤非关键日志，匹配错误特征库，输出结构化诊断报告
支持：单文件、目录递归、.tar/.tar.gz/.gz/.zip压缩包自动解压，流式处理大文件
"""

import os
import sys
import re
import gzip
import zipfile
import tarfile
import tempfile
import shutil
from datetime import datetime
from collections import defaultdict

# K8s组件识别规则：组件名 → 匹配日志路径/特征关键字
COMPONENT_RULES = [
    ("etcd", [r"etcd", r"etcd-server"]),
    ("kube-apiserver", [r"kube-apiserver", r"apiserver"]),
    ("kube-controller-manager", [r"kube-controller-manager", r"controller-manager"]),
    ("kube-scheduler", [r"kube-scheduler", r"scheduler"]),
    ("kubelet", [r"kubelet", r"kubelet\.log"]),
    ("containerd", [r"containerd", r"containerd\.log"]),
    ("docker", [r"docker\.log", r"dockerd"]),
    ("kube-proxy", [r"kube-proxy"]),
    ("calico", [r"calico", r"felix", r"bird"]),
    ("cilium", [r"cilium"]),
    ("coredns", [r"coredns"]),
    ("csi-storage", [r"csi", r"volume", r"mount", r"pv", r"pvc"]),
    ("kubeproxy", [r"kube-proxy"]),
]

# K8s错误关键字特征库：组件 → (错误关键字, 错误描述, 根因分类, 修复建议)
ERROR_SIGNATURES = {
    "all": [
        # 通用致命错误
        (r"panic:", "组件Panic崩溃", "程序崩溃", "检查对应组件版本兼容性，查看崩溃栈信息，重启组件"),
        (r"fatal error:", "致命错误", "程序崩溃", "查看详细错误栈，排查触发原因"),
        (r"x509: certificate has expired", "证书过期", "配置错误/证书问题", "使用kubeadm certs renew续期证书，重启组件"),
        (r"x509: certificate is valid for", "证书域名/IP不匹配", "配置错误", "检查证书SAN配置，重新签发证书"),
        (r"permission denied", "权限拒绝", "权限配置错误", "检查文件权限、RBAC配置、SELinux/AppArmor策略"),
        (r"connection refused", "连接被拒绝", "网络/服务异常", "检查目标服务是否启动、端口是否监听、防火墙/安全组配置"),
        (r"no such file or directory", "文件不存在", "配置/路径错误", "检查文件路径、挂载点是否正确"),
        (r"no space left on device", "磁盘空间不足", "资源不足", "清理磁盘空间，扩容节点磁盘"),
        (r"too many open files", "文件句柄耗尽", "资源限制", "调大fs.file-max和进程nofile ulimit限制"),
        (r"context deadline exceeded", "请求超时", "网络/负载过高", "检查目标服务负载、网络延迟、组件资源使用情况"),
        (r"out of memory", "OOM内存不足", "资源不足", "调大组件内存限制，排查内存泄漏，扩容节点"),
        (r"oom-killer", "进程被OOM Kill", "资源不足", "同上，检查dmesg确认OOM事件"),
        (r"failed to dial", "连接失败", "网络/服务异常", "检查目标服务状态、网络连通性"),
    ],
    "etcd": [
        (r"mvcc: database space exceeded", "etcd数据库空间超过配额", "资源配额不足", "压缩etcd历史数据，执行defrag清理空间，调大quota-backend-bytes"),
        (r"leader changed", "etcd leader频繁切换", "集群不稳定/网络分区", "检查etcd节点之间网络连通性、磁盘IO性能，避免节点负载过高"),
        (r"lost leader", "etcd丢失leader", "集群异常", "检查etcd节点健康状态、网络和磁盘IO"),
        (r"wal: sync duration", "WAL日志同步耗时过长", "磁盘IO瓶颈", "etcd必须使用高性能SSD盘，检查磁盘IO延迟，避免与其他高IO应用混部"),
        (r"request timed out", "etcd请求超时", "性能/负载问题", "检查etcd磁盘IO、网络延迟、集群负载"),
        (r"etcdserver: too many requests", "etcd请求限流", "负载过高", "扩容etcd节点，调大限流参数，排查异常高请求来源"),
        (r"member .* is unhealthy", "etcd成员不健康", "集群节点异常", "检查异常节点服务状态、日志、网络连通性"),
        (r"snapshot error", "快照失败", "磁盘/权限问题", "检查快照目录权限、磁盘空间"),
        (r"corrupt|checksum mismatch", "数据损坏", "数据一致性问题", "从健康节点恢复数据，检查磁盘坏道"),
        (r"etcdserver: mvcc: required revision has been compacted", "请求的版本已被压缩", "正常现象（非错误）", "客户端需要处理该错误重新list获取数据"),
    ],
    "kube-apiserver": [
        (r"failed calling webhook", "准入Webhook调用失败", "扩展组件异常", "检查Webhook服务是否正常、证书是否有效、网络连通性"),
        (r"webhook returned status 500|webhook returned an error", "Webhook返回错误", "扩展组件异常", "排查对应Webhook服务日志"),
        (r"forbidden: User.*cannot", "RBAC权限拒绝", "权限配置错误", "配置对应ServiceAccount/用户的RBAC权限"),
        (r"apiserver is overloaded", "APIServer过载", "资源不足/负载过高", "扩容APIServer副本，排查异常高频请求客户端"),
        (r"Too many requests", "APIServer限流", "请求量过大", "排查异常请求来源，调大限流参数或扩容"),
        (r"etcdclient: failed to connect", "连接etcd失败", "etcd异常", "优先排查etcd集群健康状态"),
        (r"failed to authenticate", "认证失败", "认证配置错误", "检查客户端证书、Token、ServiceAccount配置"),
        (r"admission webhook.*timeout", "Webhook超时", "Webhook响应慢", "优化Webhook性能，检查网络连通性"),
        (r"TLS handshake error.*EOF", "TLS握手断开", "健康检查/探针正常行为（可忽略）", "非致命错误，如非大量出现无需处理"),
        (r"failed to validate object", "资源校验失败", "配置错误", "检查提交的YAML/JSON资源配置合法性"),
    ],
    "kube-controller-manager": [
        (r"failed to sync", "控制器同步失败", "控制器异常", "检查对应控制器依赖的组件状态、日志详情"),
        (r"reconciler error", "调谐器错误", "控制器异常", "查看具体错误信息，排查资源配置问题"),
        (r"leader election lost", "控制器leader选举丢失", "高可用切换/异常", "检查网络、apiserver连通性，多副本场景下是正常切换"),
        (r"failed to create pod", "创建Pod失败", "调度/配置问题", "查看后续scheduler错误日志定位原因"),
        (r"node controller.*failed", "节点控制器异常", "节点状态异常", "检查节点状态、kubelet日志"),
        (r"deployment.*failed to create replica set", "创建RS失败", "权限/配置问题", "检查RBAC权限、Deployment配置"),
    ],
    "kube-scheduler": [
        (r"0/\d+ nodes are available", "没有可用节点调度", "调度失败", "查看后续具体不满足的调度条件（资源不足、污点、亲和性等）"),
        (r"Insufficient cpu", "CPU资源不足", "资源不足", "扩容节点CPU资源，调整Pod CPU request"),
        (r"Insufficient memory", "内存资源不足", "资源不足", "扩容节点内存资源，调整Pod memory request"),
        (r"node\(s\) had taint", "节点污点不匹配", "调度约束", "给Pod添加对应容忍，或调整节点污点"),
        (r"node affinity/selector mismatch", "节点亲和性/选择器不匹配", "调度约束", "检查Pod亲和性配置和节点标签"),
        (r"pod has unbound immediate PersistentVolumeClaims", "PVC未绑定", "存储问题", "排查PVC/PV绑定状态、存储类配置"),
        (r"didn't have free ports", "节点端口不足", "资源不足", "改用Service NodePort范围外端口，或扩容节点"),
        (r"scheduling.*failed", "调度失败", "调度异常", "查看具体失败原因"),
        (r"preemption failed", "抢占调度失败", "资源调度异常", "检查集群资源分配情况"),
    ],
    "kubelet": [
        (r"PLEG is not healthy", "PLEG（Pod生命周期事件生成器）不健康", "容器运行时卡死/IO瓶颈", "这是节点NotReady最常见原因，优先重启containerd/docker，检查磁盘IO"),
        (r"NodeHasDiskPressure", "节点磁盘压力", "资源不足", "清理磁盘空间，调整eviction-hard阈值"),
        (r"NodeHasMemoryPressure", "节点内存压力", "资源不足", "释放内存，扩容节点内存"),
        (r"NodeHasPIDPressure", "PID压力", "资源不足", "调大pid_max限制，排查进程泄漏"),
        (r"failed to rotate certificate", "证书轮换失败", "证书问题", "检查证书配置、kubelet证书目录权限"),
        (r"failed to connect to containerd|failed to connect to docker", "连接容器运行时失败", "容器运行时异常", "检查containerd/docker服务是否启动、socket文件是否存在"),
        (r"ImagePullBackOff|ErrImagePull", "镜像拉取失败", "镜像问题", "检查镜像地址是否正确、镜像仓库凭据、网络连通性"),
        (r"manifest unknown|manifest for .* not found", "镜像不存在", "镜像问题", "检查镜像标签/镜像名是否正确"),
        (r"unauthorized|authentication required", "镜像仓库认证失败", "权限问题", "配置正确的imagePullSecrets"),
        (r"MountVolume.SetUp failed", "Volume挂载失败", "存储问题", "查看具体存储插件日志，排查存储连通性/权限/配置"),
        (r"failed to setup network for sandbox", "Pod网络配置失败", "CNI网络异常", "排查Calico/Cilium等CNI插件状态"),
        (r"eviction manager: evicting pods", "驱逐Pod", "资源不足", "解决节点资源压力问题"),
        (r"cgroup.*failed", "cgroup配置错误", "配置错误", "检查cgroup驱动配置（systemd/cgroupfs）是否和容器运行时一致"),
        (r"failed to get node.*not found", "节点未注册", "注册异常", "检查kubelet bootstrap配置、apiserver连通性"),
        (r"readiness probe failed|liveness probe failed", "健康检查失败", "业务异常", "检查业务应用是否正常监听、探针配置是否合理"),
        (r"back-off restarting failed container", "容器重启崩溃", "应用异常", "查看容器业务日志排查崩溃原因"),
    ],
    "containerd": [
        (r"failed to pull image", "镜像拉取失败", "镜像/网络问题", "检查镜像地址、仓库连通性、认证信息"),
        (r"failed to create container|failed to start container", "容器创建/启动失败", "容器/配置异常", "查看具体错误信息，通常是镜像入口错误、配置错误"),
        (r"oci runtime error|runc create failed", "runc运行时错误", "容器运行时异常", "查看具体报错，常见原因：配置错误、权限不足、runc版本兼容性问题"),
        (r"failed to mount overlay", "overlay挂载失败", "存储/驱动异常", "检查overlay模块是否加载、磁盘文件系统类型、内核版本兼容性"),
        (r"no space left on device", "磁盘空间不足", "资源不足", "清理磁盘空间，清理未使用的镜像和容器"),
        (r"failed to start shim", "shim启动失败", "运行时异常", "重启containerd服务，排查shim进程异常"),
        (r"rpc error", "gRPC调用错误", "API调用异常", "查看具体错误码和消息"),
        (r"content digest mismatch", "镜像摘要不匹配", "镜像损坏", "删除镜像重新拉取"),
    ],
    "calico": [
        (r"BGP session.*not established|Failed to establish BGP session", "BGP会话未建立", "网络异常", "检查节点之间179端口连通性、Calico节点配置、AS号配置"),
        (r"no addresses available in range|IPAM allocation failed", "IP地址耗尽", "IP资源不足", "调整Calico IP池大小，检查泄漏的IP地址"),
        (r"felix.*failed to program", "Felix下发规则失败", "网络规则异常", "检查iptables/ipset规则、内核版本兼容性"),
        (r"denied by policy", "网络策略拦截", "安全策略配置", "检查NetworkPolicy配置，放通对应流量"),
        (r"failed to create veth pair", "创建veth设备失败", "网络配置异常", "检查内核模块、网络命名空间是否正常"),
        (r"bird.*error|BGP.*error", "BIRD路由错误", "路由异常", "检查BGP邻居配置、路由反射器状态"),
        (r"ipam.*failed", "IP地址分配失败", "IPAM异常", "检查IP池配置、节点IP分配情况"),
    ],
    "cilium": [
        (r"failed to load BPF program|verifier error", "eBPF程序加载失败", "内核/配置异常", "检查内核版本是否满足Cilium要求、内核配置是否开启CONFIG_BPF相关选项"),
        (r"policy verdict: DENIED", "Cilium网络策略拦截", "安全策略配置", "检查CiliumNetworkPolicy配置"),
        (r"endpoint regeneration failed", "端点再生失败", "eBPF异常", "查看详细错误，重启Cilium Pod"),
        (r"unable to connect to kube-apiserver", "连接APIServer失败", "网络/配置异常", "检查APIServer连通性、RBAC权限"),
        (r"no IPs available in pool", "IP池地址耗尽", "IP资源不足", "扩容IP池，检查泄漏的IP"),
        (r"MTU mismatch|MTU size is too large", "MTU配置错误", "网络配置错误", "调整Cilium mtu配置匹配底层网络"),
    ],
    "coredns": [
        (r"i/o timeout|SERVFAIL|NXDOMAIN", "DNS解析超时/失败", "DNS异常", "检查上游DNS连通性、CoreDNS配置、网络策略"),
        (r"failed to connect to upstream", "上游DNS连接失败", "网络异常", "检查CoreDNS到上游DNS的网络连通性、forward插件配置"),
        (r"loop detected", "DNS循环检测", "配置错误", "检查/etc/resolv.conf配置、上游DNS是否将请求转发回CoreDNS"),
        (r"plugin/forward.*error", "forward插件错误", "上游转发异常", "检查上游DNS服务器状态"),
        (r"no servers available", "无可用DNS服务器", "配置异常", "检查CoreDNS配置、上游DNS是否配置正确"),
        (r"refresh.*failed|transfer.*failed", "区域传输失败", "配置异常", "检查主从DNS配置、网络连通性"),
    ],
    "csi-storage": [
        (r"timeout expired waiting for volume to attach", "存储卷挂载超时", "存储/网络异常", "检查CSI插件是否正常运行、存储服务端状态、节点到存储网络连通性"),
        (r"failed to attach volume|failed to mount volume", "挂载卷失败", "存储异常", "查看CSI插件详细日志，检查存储端权限、LUN映射"),
        (r"permission denied", "存储权限拒绝", "权限配置错误", "检查存储导出权限、文件系统权限、SELinux配置"),
        (r"invalid credentials|authentication failed", "存储认证失败", "凭据错误", "检查CSI配置中的AccessKey/Secret是否正确"),
        (r"i/o error|input/output error", "存储IO错误", "存储链路/硬件异常", "检查存储设备状态、网络链路、多路径配置"),
        (r"volume not found", "存储卷不存在", "配置错误", "检查Volume ID是否正确、卷是否存在"),
        (r"volume expansion failed|resize not supported", "卷扩容失败", "配置/功能不支持", "检查存储类是否支持扩容、CSI驱动版本是否支持在线扩容"),
        (r"multipath.*error|device not found", "多路径设备异常", "存储链路问题", "检查多路径demon服务状态、HBA卡/光模块链路状态"),
        (r"Stale file handle", "文件句柄失效", "存储异常", "重新挂载文件系统，检查NAS服务端状态"),
    ],
}

# 非致命误报过滤规则（匹配到则忽略）
FALSE_POSITIVE_RULES = [
    (r"TLS handshake error.*EOF", "apiserver TLS健康检查断开"),
    (r"use of closed network connection", "连接正常关闭"),
    (r"context canceled", "请求正常取消"),
    (r"object has been modified", "K8s乐观锁冲突，自动重试"),
    (r"connection reset by peer", "连接正常重置"),
    (r"broken pipe", "连接断开，自动重试"),
    (r"failed to read from watch channel", "watch连接正常重连"),
    (r"etcdserver: mvcc: required revision has been compacted", "etcd版本压缩正常现象"),
    (r"no endpoints available for service", "服务启动过程中临时状态"),
    (r"node .* not found", "节点/Pod创建删除临时状态"),
]

# 日志时间格式正则（匹配常见K8s日志时间格式）
TIME_PATTERNS = [
    re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.?\d*)"),
    re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"),
    re.compile(r"^(\d{2}:\d{2}:\d{2}\.?\d*)"),
]

LOG_LEVEL_PATTERNS = [
    re.compile(r"\b(FATAL|fatal|FATAL)\b"),
    re.compile(r"\b(PANIC|panic|PANIC)\b"),
    re.compile(r"\b(ERROR|error|Error|ERR|err)\b"),
    re.compile(r"\b(WARNING|warning|WARN|warn)\b"),
]

class LogAnalyzer:
    def __init__(self):
        self.errors = defaultdict(list)  # component → list of error entries
        self.warnings = defaultdict(list)
        self.false_positives = 0
        self.total_lines = 0
        self.file_stats = defaultdict(int)  # file → line count
        self.component_file_map = defaultdict(list)  # component → list of files
        self.first_error_time = None
        self.first_error_component = None
        self.first_error_msg = None

    def detect_component(self, filepath):
        """根据文件路径检测属于哪个K8s组件"""
        filepath_lower = filepath.lower()
        for comp_name, patterns in COMPONENT_RULES:
            for pat in patterns:
                if re.search(pat, filepath_lower):
                    return comp_name
        return "unknown"

    def match_errors(self, line, component):
        """匹配行中的错误特征，返回匹配到的错误列表"""
        matched = []
        # 先匹配组件特定错误，再匹配通用错误
        all_signatures = ERROR_SIGNATURES.get(component, []) + ERROR_SIGNATURES.get("all", [])
        for pattern, desc, category, suggestion in all_signatures:
            if re.search(pattern, line, re.IGNORECASE):
                matched.append((pattern, desc, category, suggestion))
        return matched

    def is_false_positive(self, line):
        """判断是否为误报/可忽略日志"""
        for pattern, reason in FALSE_POSITIVE_RULES:
            if re.search(pattern, line, re.IGNORECASE):
                return reason
        return None

    def extract_time(self, line):
        """提取日志时间戳"""
        for pat in TIME_PATTERNS:
            m = pat.match(line)
            if m:
                return m.group(1)
        return None

    def extract_log_level(self, line):
        """提取日志级别"""
        for i, pat in enumerate(LOG_LEVEL_PATTERNS):
            if pat.search(line):
                return ["FATAL", "PANIC", "ERROR", "WARNING"][i]
        return "INFO"

    def process_line(self, line, component, filepath, line_num):
        """处理单行日志"""
        self.total_lines += 1
        line = line.rstrip("\n\r")
        if not line.strip():
            return
        log_level = self.extract_log_level(line)
        if log_level not in ["FATAL", "PANIC", "ERROR", "WARNING"]:
            return
        # 检查是否误报
        fp_reason = self.is_false_positive(line)
        if fp_reason:
            self.false_positives += 1
            return
        # 提取时间
        log_time = self.extract_time(line)
        # 匹配错误
        errors = self.match_errors(line, component)
        entry = {
            "time": log_time,
            "level": log_level,
            "line_num": line_num,
            "filepath": filepath,
            "component": component,
            "line": line[:500],  # 截断长行
            "matched_errors": errors,
        }
        if log_level in ["FATAL", "PANIC", "ERROR"]:
            self.errors[component].append(entry)
            # 记录第一个错误（根因）
            if not self.first_error_time and log_time:
                self.first_error_time = log_time
                self.first_error_component = component
                self.first_error_msg = line[:200]
        elif log_level == "WARNING":
            self.warnings[component].append(entry)

    def process_file(self, filepath):
        """处理单个日志文件"""
        component = self.detect_component(filepath)
        self.component_file_map[component].append(filepath)
        # 判断是否为gzip压缩
        if filepath.endswith(".gz"):
            opener = gzip.open
            mode = "rt"
        else:
            opener = open
            mode = "r"
        try:
            with opener(filepath, mode, encoding="utf-8", errors="replace") as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    self.file_stats[filepath] = line_num
                    self.process_line(line, component, filepath, line_num)
        except Exception as e:
            self.errors["unknown"].append({
                "time": None,
                "level": "ERROR",
                "line_num": 0,
                "filepath": filepath,
                "component": "unknown",
                "line": f"Failed to read file: {str(e)}",
                "matched_errors": [],
            })

    def process_directory(self, dirpath):
        """递归处理目录下所有日志文件"""
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                fpath = os.path.join(root, f)
                if os.path.isfile(fpath) and not f.startswith("."):
                    # 跳过明显的非日志文件
                    if f.endswith((".pyc", ".so", ".o", ".a", ".png", ".jpg", ".gif")):
                        continue
                    self.process_file(fpath)

    def process_tar(self, tarpath):
        """处理tar/tar.gz压缩包，解压到临时目录后处理"""
        tmpdir = tempfile.mkdtemp(prefix="k8slog_")
        try:
            with tarfile.open(tarpath, "r:*") as tf:
                tf.extractall(tmpdir)
            self.process_directory(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def process_zip(self, zippath):
        """处理zip压缩包"""
        tmpdir = tempfile.mkdtemp(prefix="k8slog_")
        try:
            with zipfile.ZipFile(zippath) as zf:
                zf.extractall(tmpdir)
            self.process_directory(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def process_path(self, path):
        """处理任意路径：文件/目录/压缩包自动识别"""
        if not os.path.exists(path):
            print(f"Error: Path {path} not found", file=sys.stderr)
            return
        if os.path.isdir(path):
            self.process_directory(path)
        elif os.path.isfile(path):
            if path.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")):
                self.process_tar(path)
            elif path.endswith(".zip"):
                self.process_zip(path)
            else:
                self.process_file(path)

    def generate_report(self, output_path=None):
        """生成结构化诊断报告"""
        report = []
        report.append("# 📌 K8s集群故障诊断报告\n")
        report.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**总日志行数**: {self.total_lines:,}")
        report.append(f"**识别到组件**: {', '.join([c for c in self.component_file_map if self.component_file_map[c]])}")
        report.append(f"**过滤非致命告警**: {self.false_positives} 条")
        report.append(f"**发现ERROR级错误**: {sum(len(errs) for errs in self.errors.values())} 条")
        report.append(f"**发现WARNING级告警**: {sum(len(warns) for warns in self.warnings.values())} 条\n")

        # 根因概览
        report.append("### 1. 根因概览")
        if self.first_error_component:
            report.append(f"- **首个致命错误时间**: {self.first_error_time}")
            report.append(f"- **异常组件**: {self.first_error_component}")
            report.append(f"- **错误信息**: {self.first_error_msg}\n")
            # 提取根因分类和建议
            if self.errors[self.first_error_component]:
                first_err = self.errors[self.first_error_component][0]
                if first_err["matched_errors"]:
                    _, desc, category, suggestion = first_err["matched_errors"][0]
                    report.append(f"- **根因分类**: {category}")
                    report.append(f"- **问题描述**: {desc}")
                    report.append(f"- **初步修复建议**: {suggestion}\n")
        else:
            report.append("- ✅ 未发现明确ERROR级致命错误，集群状态基本正常\n")

        # 按组件展示错误
        report.append("### 2. 组件错误详情")
        for component, errs in sorted(self.errors.items(), key=lambda x: -len(x[1])):
            if not errs:
                continue
            report.append(f"#### 2.{len(report)-2} {component} 组件（{len(errs)}条错误）")
            # 去重相同错误（相同pattern+line取前3条）
            seen_patterns = defaultdict(int)
            for err in errs[:10]:  # 最多展示前10条错误
                if err["matched_errors"]:
                    pat_key = err["matched_errors"][0][1]
                    seen_patterns[pat_key] += 1
                    if seen_patterns[pat_key] > 3:
                        continue
                    _, desc, category, suggestion = err["matched_errors"][0]
                    time_str = f"[{err['time']}] " if err["time"] else ""
                    report.append(f"- {time_str}**{err['level']}**: {desc}")
                    report.append(f"  - 位置: `{os.path.basename(err['filepath'])}` 第{err['line_num']}行")
                    report.append(f"  - 分类: {category}")
                    report.append(f"  - 日志: `{err['line']}`")
                    report.append(f"  - 建议: {suggestion}")
                else:
                    time_str = f"[{err['time']}] " if err["time"] else ""
                    report.append(f"- {time_str}**{err['level']}**: {err['line']}")
                    report.append(f"  - 位置: `{os.path.basename(err['filepath'])}` 第{err['line_num']}行")
            if len(errs) > 10:
                report.append(f"\n- （其余{len(errs)-10}条相似错误已省略）\n")

        # 警告信息
        total_warns = sum(len(w) for w in self.warnings.values())
        if total_warns > 0:
            report.append("### 3. 警告信息（非致命，但需关注）")
            warn_count = 0
            for component, warns in self.warnings.items():
                for warn in warns[:3]:  # 每个组件最多展示3条警告
                    if warn_count >= 10:
                        break
                    time_str = f"[{warn['time']}] " if warn["time"] else ""
                    report.append(f"- {time_str}{component}: `{warn['line'][:200]}`")
                    warn_count += 1
            if total_warns > warn_count:
                report.append(f"\n- （其余{total_warns - warn_count}条警告已省略）\n")

        # 修复优先级建议
        report.append("### 4. 修复优先级建议")
        priority_tasks = []
        # etcd最高优先级
        if self.errors.get("etcd"):
            priority_tasks.append("1. **最高优先级**：先排查etcd集群健康状态，etcd异常会导致整个控制面不可用，参考上述etcd错误建议修复")
        # 控制平面其次
        if self.errors.get("kube-apiserver"):
            priority_tasks.append("2. **高优先级**：排查kube-apiserver错误，确认etcd连接正常、Webhook服务健康")
        # 节点问题
        if self.errors.get("kubelet") or self.errors.get("containerd"):
            priority_tasks.append("3. **高优先级**：节点侧kubelet/containerd异常，优先处理PLEG不健康、磁盘压力、容器运行时故障问题")
        # 网络问题
        if self.errors.get("calico") or self.errors.get("cilium") or self.errors.get("coredns"):
            priority_tasks.append("4. **中优先级**：网络组件异常，排查CNI插件、CoreDNS、网络策略配置问题")
        # 存储问题
        if self.errors.get("csi-storage"):
            priority_tasks.append("5. **中优先级**：存储挂载异常，排查CSI插件、存储服务端连通性和权限配置")
        # 调度问题
        if self.errors.get("kube-scheduler"):
            priority_tasks.append("6. **中优先级**：Pod调度失败，根据调度错误信息调整资源配置、节点污点/亲和性")

        if not priority_tasks:
            if self.first_error_component:
                priority_tasks.append(f"1. 优先排查{self.first_error_component}组件错误，根据上述建议修复后观察集群状态")
            else:
                priority_tasks.append("1. 集群无严重错误，可结合业务现象进一步确认问题")

        for task in priority_tasks:
            report.append(f"- {task}")

        report.append("\n### 5. 验证方法")
        report.append("修复完成后执行以下命令验证集群状态：")
        report.append("```bash")
        report.append("kubectl get nodes  # 确认所有节点Ready")
        report.append("kubectl get pods -A  # 确认所有Pod正常Running")
        report.append("kubectl get componentstatuses  # 确认控制平面组件健康")
        report.append("```")

        report_content = "\n".join(report)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            print(f"报告已生成: {output_path}", file=sys.stderr)
        return report_content

def main():
    if len(sys.argv) < 2:
        print("用法: python3 k8s_log_preprocess.py <日志路径(文件/目录/压缩包)> [输出报告路径]")
        print("示例:")
        print("  python3 k8s_log_preprocess.py /var/log/k8s/ k8s_diagnose_report.md")
        print("  python3 k8s_log_preprocess.py k8s-logs.tar.gz")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    if not output_path:
        # 默认输出路径
        base_name = os.path.basename(input_path.rstrip("/"))
        output_path = f"k8s_diagnose_{base_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    analyzer = LogAnalyzer()
    print(f"正在分析日志: {input_path}", file=sys.stderr)
    analyzer.process_path(input_path)
    report = analyzer.generate_report(output_path)
    print(report)

if __name__ == "__main__":
    main()
