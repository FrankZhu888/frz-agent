#!/usr/bin/env python3
import os
import sys
from typing import List, Tuple

# 可扩展错误关键字列表（分层设计）
# 核心通用与系统级错误
CORE_ERRORS = {
    'ERROR', 'FATAL', 'CRITICAL', 'Exception', 'Traceback', 'Timeout',
    'Connection refused', 'Out of memory', 'too many open files',
    'Access denied', 'Deadlock', 'panic:', 'fatal error:', 'crash',
    'segmentation fault', 'core dumped', 'OOM', 'StackOverflow',
    'Connection reset by peer', 'No route to host', 'Disk quota exceeded',
    '502', '503'
}

# 1. 大模型推理框架专属 (vLLM / Triton / TensorRT-LLM / SGLang / PyTorch)
AI_LLM_ERRORS = {
    'CUDA error', 'CUDA out of memory', 'NCCL WARN', 'NCCL ERR', 
    'TensorRT error', 'TritonServer Exception', 'engine build failed', 
    'shape mismatch', 'OOMError: CUDA', 'CUDNN_STATUS', 
    'allocator failed', 'illegal memory access', 'invalid device ordinal',
    'RuntimeError: CUDA', 'NaN detected', 'loss diverged', 
    'distributed init failed', 'gradient overflow'
}

# 2. 云原生与 K8s 集群专属 (Kubelet / Containerd / Pods)
K8S_CLOUD_ERRORS = {
    'CrashLoopBackOff', 'OOMKilled', 'Evicted', 'FailedScheduling',
    'FailedCreatePodSandBox', 'NodeNotReady', 'NetworkPlugin cni failed',
    'Volume binding failed', 'PLEG is not healthy', 'Sandbox creation failed',
    'rpc error: code =', 'context deadline exceeded',
    'ReadinessProbe failed', 'LivenessProbe failed', 'ImagePullBackOff', 
    'ErrImagePull'
}

# 3. 主流开源中间件 (MySQL / Redis / Kafka / Nginx)
MIDDLEWARE_ERRORS = {
    # MySQL
    'Deadlock found', 'Lock wait timeout', 'Got error 28', 'Too many connections', 'server has gone away',
    # Redis
    'OOM command not allowed', 'MASTERDOWN', 'LOADING Redis is loading', 'BUSY Redis is busy',
    # Kafka
    'Broker may not be available', 'NotLeaderOrFollowerException', 'NetworkException', 'LEADER_NOT_AVAILABLE', 'Rebalance in progress',
    # Nginx
    '502 Bad Gateway', '504 Gateway Time-out', 'worker process exited on signal', 'no live upstreams', 'upstream timed out'
}

# 4. 主流编程语言业务报错特征 (Java / Go / Python)
LANGUAGE_ERRORS = {
    # Java
    'java.lang.OutOfMemoryError', 'NullPointerException', 'GC overhead limit exceeded', 'UnsatisfiedLinkError', 'ConcurrentModificationException',
    # Go
    'panic: runtime error', 'fatal error: concurrent map', 'goroutine stack exceeds',
    # Python
    'Traceback (most recent call last):', 'ModuleNotFoundError', 'RecursionError', 'IndentationError'
}

# 汇总为一个超级集合用于高速正则匹配
ERROR_KEYWORDS = CORE_ERRORS | AI_LLM_ERRORS | K8S_CLOUD_ERRORS | MIDDLEWARE_ERRORS | LANGUAGE_ERRORS

# 错误行前后上下文窗口大小
CONTEXT_WINDOW = 5

def is_stack_trace_line(line: str) -> bool:
    """判断是否为堆栈跟踪行（缩进开头/Java/C#/Python堆栈特征）"""
    stripped = line.lstrip()
    return (line.startswith((' ', '\t')) 
            or stripped.startswith(('at ', 'Caused by: ', '... ', 'File "', 'Traceback '))
            or stripped.startswith(('Exception in thread ', 'caused by: ', 'raise ')))

def extract_error_context(log_file_path: str) -> List[Tuple[int, List[str]]]:
    """
    提取日志中所有错误的上下文片段
    返回：[(错误起始行号, 上下文行列表)]
    """
    file_size = os.path.getsize(log_file_path)
    if file_size > 5 * 1024 * 1024:
        print(f"[预处理提示] 日志文件大小{file_size/1024/1024:.2f}MB，超过5MB，仅提取错误上下文片段\n")

    errors = []
    line_buffer = []  # 滚动缓存最近 CONTEXT_WINDOW * 2 + 1 行，用于获取前上下文
    pending_post_context = 0  # 待收集的后上下文行数

    with open(log_file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.rstrip('\n')
            line_buffer.append((line_num, line))
            
            # 维持滚动缓存大小
            if len(line_buffer) > CONTEXT_WINDOW * 2 + 1:
                line_buffer.pop(0)

            # 检查当前行是否包含错误
            has_error = any(keyword in line for keyword in ERROR_KEYWORDS)
            if has_error:
                # 提取前上下文：从当前行往前最多CONTEXT_WINDOW行
                start_idx = max(0, len(line_buffer) - CONTEXT_WINDOW - 1)
                context_lines = [l for _, l in line_buffer[start_idx:]]
                error_start_line = line_buffer[start_idx][0]
                pending_post_context = CONTEXT_WINDOW  # 开始收集后5行上下文
                errors.append((error_start_line, context_lines))
            elif pending_post_context > 0:
                # 收集后上下文
                errors[-1][1].append(line)
                pending_post_context -= 1
                # 如果是堆栈行，自动延长上下文收集直到堆栈结束
                if is_stack_trace_line(line):
                    pending_post_context += 1

    # 去重重叠的错误片段
    unique_errors = []
    last_end_line = 0
    for start_line, context in errors:
        end_line = start_line + len(context) - 1
        if start_line > last_end_line:
            unique_errors.append((start_line, context))
            last_end_line = end_line

    return unique_errors

def main():
    if len(sys.argv) != 2:
        print("用法: python3 log_preprocess.py <日志文件路径>")
        sys.exit(1)

    log_path = sys.argv[1]
    if not os.path.exists(log_path):
        print(f"错误: 文件不存在 {log_path}")
        sys.exit(1)

    error_contexts = extract_error_context(log_path)

    if not error_contexts:
        print("未发现标准错误特征")
        return

    for idx, (start_line, context) in enumerate(error_contexts, 1):
        print(f"===== 错误 {idx} (起始行号: {start_line}) =====")
        print('\n'.join(context))
        print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    main()