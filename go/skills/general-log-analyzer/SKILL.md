---
name: general-log-analyzer
description: 通用应用层日志分析器，支持各类开源组件（Nginx/Redis/MySQL/Kafka/Java/Go/Python等）日志的智能归因与排障，无需预先知道应用类型
activate_when:
  - 用户上传日志文件（.log/.txt/.tar.gz/.zip等格式）
  - 用户提到日志分析、报错排查、异常定位、程序崩溃等场景
  - 用户提供Nginx/Redis/MySQL/Kafka/Java/Go/Python等组件的日志内容
---

# general-log-analyzer 技能定义
## 1. 核心目标
这是一个通用的应用层日志分析器，用于分析客户提供的各类开源组件日志（如Nginx, Redis, MySQL, Kafka, Java/Go/Python业务日志等），在不预先知道应用类型的情况下，进行智能归因和排障。

## 2. 预处理逻辑
执行分析前先运行内置的Python预处理脚本，过滤逻辑如下：
- **通用错误特征匹配**：匹配广泛的错误关键字，包括但不限于：`ERROR, FATAL, Exception, Traceback, Timeout, Connection refused, Out of memory, too many open files, Access denied, 502, 503, Deadlock, panic, segmentation fault, OOM`
- **上下文捕获**：当匹配到错误关键字时，严禁只提取单行，必须提取该错误行的前后5行上下文；如果检测到连续的空格缩进（如Java/Python的Stack Trace），必须将整个堆栈块作为一个整体提取
- **大文件处理**：日志文件大于5MB时，仅提取错误上下文片段，禁止直接读取全量文本，避免内存溢出

## 3. LLM分析逻辑（自适应识别）
拿到预处理后的错误片段后，执行以下分析：
- **应用识别**：根据日志格式和错误堆栈，自动推断应用类型/技术栈，例如：看到`org.springframework`推断为Java/Spring，看到`mysqld`推断为MySQL，看到`nginx:`推断为Nginx
- **语义归因**：不要机械翻译报错，要解释业务影响，例如：看到`too many open files`，除了指出句柄耗尽，还要建议检查`ulimit`配置或应用连接泄露问题
- **优先级排序**：多个错误同时存在时，优先分析最早发生的根因错误，过滤无关的次生错误

## 4. 输出格式规范
严格按照以下固定格式输出：
```
🧩 通用应用日志分析报告
* **应用类型推测**: [推断出的应用名称/技术栈，例如：Nginx / Java Spring Boot / Redis 6.2]
* **核心异常摘要**: [用一句话概括最主要的报错及影响，例如：数据库连接池耗尽导致业务接口10:30之后大量超时]
* **关键日志证据**: [仅展示最具代表性的1-2段带上下文的错误堆栈，避免冗余]
* **根因与修复建议**: [给出针对该技术栈的专业二线排查建议，可落地可执行]
```

## 5. 约束限制
- **拒绝大文件透传**：大于5MB的日志文件必须依赖Python预处理脚本缩减，禁止直接读取全量文本传递给LLM
- **专业克制**：如果预处理后没有任何明确的错误关键字，必须明确告知「未发现标准错误特征」，禁止凭空捏造故障原因
- **不跨领域臆测**：仅基于日志内容分析，不要关联日志中未提及的其他组件/系统问题
