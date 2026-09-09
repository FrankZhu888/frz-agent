#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

# 错误模式定义
ERROR_PATTERNS = {
    'grub': [
        r'error: file not found',
        r'grub rescue>',
        r'error: no such partition',
        r'error: unknown filesystem',
        r'error: you need to load the kernel first'
    ],
    'initramfs': [
        r"can't find UUID",
        r'fsck failed',
        r'mount: / not found',
        r'ALERT! /dev/.* does not exist\. Dropping to a shell!',
        r'initramfs:',
        r'Unable to mount root fs'
    ],
    'kernel_panic': [
        r'Kernel panic - not syncing',
        r'Oops:',
        r'Segfault at',
        r'Hardware Error',
        r'Machine Check Exception',
        r'BUG: unable to handle kernel',
        r'general protection fault:'
    ],
    'hardware': [
        r'PCIe Bus Error',
        r'DRAM ECC Error',
        r'CPU[0-9]*: Core temperature above threshold',
        r'I/O error, dev',
        r'read error, sector'
    ]
}

# 噪声过滤规则
NOISE_PATTERNS = [
    r'datadog.* error',
    r'NetworkManager.* warning',
    r'usb.* new high-speed USB device',
    r'acpi.*: [A-Z]+_.*',
    r'NFSD: Using',
    r'tcp.*: peer <.*>:\d+ requested disconnect'
]

class ConsoleLogAnalyzer:
    def __init__(self, log_content):
        self.content = log_content
        self.lines = log_content.split('\n')
        self.errors = defaultdict(list)
        self.key_evidence = []
        self.fault_phase = 'Unknown'
        self.core_conclusion = ''
        self.recommended_action = ''
        self.root_cause = ''
        self.steps = []
        
    def filter_noise(self):
        """过滤噪声日志"""
        filtered_lines = []
        for line in self.lines:
            is_noise = False
            for pattern in NOISE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    is_noise = True
                    break
            if not is_noise and line.strip():
                filtered_lines.append(line.strip())
        self.filtered_lines = filtered_lines
        
    def identify_errors(self):
        """识别错误类型"""
        # 检查GRUB错误
        for pattern in ERROR_PATTERNS['grub']:
            for line in self.filtered_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    self.errors['grub'].append(line)
                    if self.fault_phase == 'Unknown':
                        self.fault_phase = 'GRUB Phase'
        
        # 检查Initramfs错误
        for pattern in ERROR_PATTERNS['initramfs']:
            for line in self.filtered_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    self.errors['initramfs'].append(line)
                    if self.fault_phase == 'Unknown':
                        self.fault_phase = 'Initramfs Phase'
        
        # 检查内核崩溃错误
        for pattern in ERROR_PATTERNS['kernel_panic']:
            for line in self.filtered_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    self.errors['kernel_panic'].append(line)
                    if self.fault_phase == 'Unknown':
                        self.fault_phase = 'Kernel Panic'
        
        # 检查硬件错误
        for pattern in ERROR_PATTERNS['hardware']:
            for line in self.filtered_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    self.errors['hardware'].append(line)
                    if self.fault_phase == 'Unknown':
                        self.fault_phase = 'Hardware Error'
        
        # 合并堆栈跟踪
        self._merge_stack_traces()
        
    def _merge_stack_traces(self):
        """合并多行堆栈跟踪"""
        in_stack = False
        current_stack = []
        for line in self.filtered_lines:
            if re.match(r'^Call Trace:', line) or re.match(r'^Trace:', line):
                in_stack = True
                current_stack = [line]
            elif in_stack:
                if re.match(r'^---\s+end trace|^Code:|^[A-Z][a-z]+:', line):
                    in_stack = False
                    if len(current_stack) > 2:
                        self.key_evidence.append('\n'.join(current_stack[:3]) + '\n...')
                else:
                    current_stack.append(line)
    
    def analyze(self):
        """执行分析"""
        self.filter_noise()
        self.identify_errors()
        
        # 提取关键证据（最多3条）
        all_errors = []
        for err_type in self.errors:
            all_errors.extend(self.errors[err_type])
        
        # 去重并取前3条
        unique_errors = list(dict.fromkeys(all_errors))
        self.key_evidence.extend(unique_errors[:3])
        
        # 生成结论和建议
        if 'grub' in self.errors and len(self.errors['grub']) > 0:
            self.core_conclusion = "GRUB引导失败，系统无法启动，影响所有业务，严重程度高"
            self.recommended_action = "进入GRUB救援模式修复引导配置，或使用Live CD重建GRUB"
            self.root_cause = "GRUB引导配置损坏或引导分区丢失，导致系统无法找到内核或根分区，启动失败进入grub rescue模式"
            self.steps = [
                "重启系统，在GRUB菜单按'c'进入命令行模式",
                "查看可用分区：`ls`",
                "查找引导分区：`ls (hd0,msdos1)/`",
                "手动引导系统后重建GRUB：`grub2-install /dev/sda && grub2-mkconfig -o /boot/grub2/grub.cfg`"
            ]
        
        elif 'initramfs' in self.errors and len(self.errors['initramfs']) > 0:
            for line in self.key_evidence:
                if 'fsck failed' in line or 'ext4_fs error' in line.lower():
                    self.core_conclusion = "根分区文件系统损坏，启动失败，所有业务中断，严重程度高"
                    self.recommended_action = "使用Rescue模式引导，执行fsck修复根分区文件系统"
                    self.root_cause = "根分区文件系统元数据损坏，fsck检查失败导致无法挂载根文件系统，系统进入initramfs紧急模式"
                    self.steps = [
                        "使用系统安装U盘引导进入救援模式",
                        "修复文件系统：`fsck.ext4 -y /dev/sda1`（替换为实际根分区设备）",
                        "修复完成后重启系统验证"
                    ]
                    break
            else:
                self.core_conclusion = "Initramfs初始化失败，无法挂载根分区，系统启动失败"
                self.recommended_action = "检查/etc/fstab配置及根分区UUID是否正确"
                self.root_cause = "根分区UUID变更或fstab配置错误，导致系统无法找到并挂载根文件系统"
                self.steps = [
                    "进入救援模式，查看blkid输出确认根分区UUID",
                    "比对/etc/fstab中的UUID配置是否正确",
                    "修正配置后重启系统"
                ]
        
        elif 'kernel_panic' in self.errors and len(self.errors['kernel_panic']) > 0:
            for line in self.key_evidence:
                if 'Hardware Error' in line or 'Machine Check' in line:
                    self.core_conclusion = "硬件故障触发内核崩溃，系统异常重启，业务中断，严重程度高"
                    self.recommended_action = "立即排查硬件故障，优先检查CPU、内存、磁盘"
                    self.root_cause = "硬件层面检测到不可纠正错误（如CPU缓存错误、内存ECC错误），触发内核崩溃保护机制"
                    self.steps = [
                        "收集硬件日志（BMC/IPMI日志）",
                        "运行内存检测：`memtest86+`",
                        "检测磁盘健康状态：`smartctl -a /dev/sda`",
                        "若硬件故障，更换故障部件"
                    ]
                    break
            else:
                self.core_conclusion = "内核崩溃，系统异常重启，业务中断"
                self.recommended_action = "收集完整kdump日志分析根因，临时升级内核规避"
                self.root_cause = "内核触发异常（如空指针引用、内存越界），导致系统崩溃"
                self.steps = [
                    "检查/var/crash/下的kdump崩溃日志",
                    "确认是否有第三方内核模块加载导致问题",
                    "尝试升级到最新稳定内核版本"
                ]
        
        elif 'hardware' in self.errors and len(self.errors['hardware']) > 0:
            self.core_conclusion = "硬件异常，可能导致系统不稳定或IO错误，影响业务可用性"
            self.recommended_action = "排查对应硬件部件健康状态"
            self.root_cause = "检测到硬件层面异常（如PCIe总线错误、磁盘IO错误、温度告警）"
            self.steps = [
                "查看BMC硬件监控状态",
                "对故障部件进行诊断测试",
                "必要时更换故障硬件"
            ]
        
        else:
            self.core_conclusion = "未检测到严重系统故障，建议提供更多上下文日志"
            self.recommended_action = "提供完整的dmesg或/var/log/messages日志"
            self.fault_phase = "Application Error/Unknown"
            self.root_cause = "当前日志片段未包含足够的故障信息，无法定位根因"
            self.steps = [
                "收集完整的系统日志：`dmesg > dmesg.log && tar zcvf logs.tar.gz /var/log/`",
                "提供故障发生前后的操作上下文"
            ]
    
    def generate_report(self):
        """生成报告"""
        report = """### 🚨 故障快速响应 (Incident Response)
* **核心结论**: {core_conclusion}
* **推荐动作**: `{recommended_action}`
* **故障阶段**: {fault_phase}

### 🔍 关键证据 (Evidence)
""".format(
    core_conclusion=self.core_conclusion,
    recommended_action=self.recommended_action,
    fault_phase=self.fault_phase
)
        
        for evi in self.key_evidence:
            report += f"* `{evi}`\n"
        
        report += """
### 🛠 排查指南 (Troubleshooting)
* **根因分析**: {root_cause}
* **操作步骤**:
""".format(root_cause=self.root_cause)
        
        for i, step in enumerate(self.steps, 1):
            if step.startswith('`'):
                report += f"  {i}. {step}\n"
            else:
                report += f"  {i}. {step}\n"
        
        report += """
---
*(若需查看完整原始日志或统计数据，请回复 "详细日志" 或 "统计报告")*"""
        
        # 短日志上下文感知
        if len(self.filtered_lines) < 10 and self.fault_phase in ['GRUB Phase', 'Initramfs Phase']:
            report = "是否为系统启动阶段报错？如果是，建议优先进入 Rescue 模式。\n\n" + report
        
        return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <log_file>")
        print("Or pipe log content: cat dmesg.log | python analyzer.py")
        sys.exit(1)
    
    if sys.argv[1] == '-':
        content = sys.stdin.read()
    else:
        try:
            with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    
    analyzer = ConsoleLogAnalyzer(content)
    analyzer.analyze()
    print(analyzer.generate_report())
