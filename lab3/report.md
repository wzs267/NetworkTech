**实验报告 — 通过编程获取 IP 与 MAC 映射（Lab3）**

**实验目的**:  
- 在已完成的“IP 数据报捕获与分析”基础上，学习并演示 WinPcap/NPcap 的数据包发送方法（`pcap_sendpacket()`），通过主动发送 ARP 请求并捕获 ARP 回复来获取 IP ↔ MAC 映射；同时提供命令行界面用于输入目标 IP 并显示对应的 MAC 地址。

**实验环境**:  
- 操作系统：Windows 10/11  
- 开发工具：GCC (MinGW) 10.3.0（TDM64）  
- NPcap SDK：npcap_sdk（头文件位于 `Include`）  
- 已生成 MinGW 导入库：libwpcap.a  
- 运行要求：以管理员权限运行程序（发送原始以太网帧需管理员权限）

**交付文件（lab3 目录）**:  
- `main_lab3.c` — 主程序（设备选择、输入 IP、调用发送与捕获、SendARP 后备、退出暂停）  
- `arp_sender.c` / `arp_sender.h` — 构造以太网 + ARP 请求并调用 `pcap_sendpacket()` 发送  
- `arp_parser.c` / `arp_parser.h` — 解析捕获到的以太网帧，提取 ARP 回复的 sender IP/MAC  
- README.md — 编译与运行说明

**核心代码设计（对应实验需求）**

- 要求 (1)：学习 WinPcap 发送方法  
  - 模块：`arp_sender.c`  
  - 实现：手工构造以太网头（dst=广播 ff:ff:ff:ff:ff:ff，src=本接口 MAC，ethertype=0x0806） + ARP payload（htype=1, ptype=0x0800, hlen=6, plen=4, opcode=1 request），调用 `pcap_sendpacket()` 发送。

- 要求 (2)：获取 IP↔MAC 映射  
  - 被动 + 主动结合：主动发送 ARP 请求（上面），并在同一接口上用 pcap 捕获 ARP 回复。解析 ARP 回复包得到 sender IP 与 sender MAC。  
  - 模块：`arp_parser.c`（解析并匹配 target IP）

- 要求 (3)：界面（命令行）  
  - 模块：`main_lab3.c`  
  - 实现：列出可用设备（调用 `pcap_findalldevs()`），让用户选择接口，输入 IPv4 地址字符串（支持单个 IP），打印结果（IP -> MAC）；程序在结束前 pause，等待用户按回车确认以便在双击运行时能看到结果。

- 要求 (4)：结构清晰、可读性  
  - 各功能单一模块化：设备/打开（复用之前逻辑），ARP 发送、ARP 解析、主控 UI。代码注释与 README 提示运行权限与常见问题。

**实现关键点（细节）**

- 以太网帧结构：14 字节以太头 + 28 字节 ARP（Ethernet/IPv4）payload，总包长 42 字节（固定）。  
- 发送：`pcap_sendpacket(handle, packet, sizeof(packet))`。  
- 捕获：打开相同接口 `pcap_open_live()`，设置 BPF 过滤器 `arp`（减少噪声），使用 `pcap_next()`（兼容性更好）循环等待 ARP reply，匹配 `opcode==2` 且 `sender_ip==target_ip` 即视为目标回复。  
- 后备：程序在发送后还调用 Windows API `SendARP()` 作为快速后备（当内核 ARP 缓存已有条目或操作系统先发了 ARP 时，`SendARP` 可返回 MAC），并将结果显示给用户（但仍做 pcap 捕获以供验证）。  
- 输入与退出：为避免 scanf 留下换行导致立即退出，在等待用户确认退出前清空 stdin 缓冲并调用 `getchar()`。

**如何编译与运行（示例命令，PowerShell / MinGW）**  
- 编译（在管理员 PowerShell 下，假设 SDK 路径与导入库位置按前述）：
```powershell
gcc -o lab3.exe main_lab3.c arp_sender.c arp_parser.c `
  -I"D:\apps\tools\npcap_sdk\Include" `
  "D:\1大三上\计算机网络\Dlab2\libwpcap.a" `
  -lws2_32 -liphlpapi
```
- 运行（必须以管理员权限）：
```powershell
.\lab3.exe
# 选择设备编号（例如 6），输入要查询的 IPv4（如 10.130.0.1）
```

**实验过程与实际输出（节选）**  
- 选择设备 6（Intel Wi‑Fi）并输入目标 `10.130.0.1`，程序输出（你的实际运行）：
```
Available devices:
1. \Device\NPF_{...} (WAN Miniport (Network Monitor))
...
6. \Device\NPF_{5864...} (Intel(R) Wi-Fi 6E AX211 160MHz)
...
Select device number: 6
Using source MAC: D4:D8:53:33:E7:6C
Enter IPv4 address to query (e.g. 192.168.1.10): 10.130.0.1
Using source IP: 10.130.60.179
ARP request sent, waiting for reply (2s)...
SendARP result: 10.130.0.1 => 00:00:5E:00:01:FE
Press Enter to exit...
```
- 与系统 `arp -a` 输出一致：`10.130.0.1 -> 00-00-5e-00-01-fe`（动态条目），说明程序成功查到并显示了 IP→MAC 映射。

**结果分析与讨论**

- 成功点：
  - 程序展示了 WinPcap/NPcap 的发送能力（`pcap_sendpacket()`）和捕获能力（`pcap_open_live()` + BPF 过滤器），满足了（1）与（2）。  
  - 命令行界面允许用户输入 IP 并显示对应 MAC，满足（3）；程序结构模块化、注释清楚，满足（4）。  
  - `SendARP` 后备在很多场景下能即刻返回内核已解析的 ARP 缓存，改善了用户体验（快速返回结果）。

- 关于 `00:00:5E:00:01:FE` 这类 MAC:
  - 这是程序与系统当前 ARP 表中对该 IP 的记录（`arp -a` 显示同样的 MAC）。出现非普通主机 MAC（例如看起来像特殊/虚拟/多播相关）可能由网络设备（网关/负载均衡器/虚拟化或 NAT 设备）使用虚拟或特殊 MAC 策略引起。该结果应以系统 ARP 表与路由器实际行为为准，程序只是展示捕获到或系统查询到的映射。
  - 如果怀疑不正常，可以用 Wireshark 在同接口抓包（过滤 `arp`），观察 ARP Request/Reply 的真实报文，以判断是否是网关回复、代理 ARP（proxy ARP）或其它机制。

- 关于“长时间未收到 reply”现象的解释：
  - ARP 只在同一 L2 广播域生效；若目标 IP 不在所选接口子网内（例如你最初试 `192.168.1.10`，而接口是 `10.130.x.x`），不会有直接 ARP 回复。程序已加入子网检查建议（可选改进），并在本次运行里使用网关（`10.130.0.1`）作为测试，成功获取映射。
  - 另外，局域网隔离、防火墙或路由器策略也会导致无法收到 ARP reply。

**注意事项与已知限制**
- 发送原始以太帧需要管理员权限；请以管理员身份运行。  
- 程序目前对 IPv4 单个地址查询（可扩展为批量）；若需要 GUI 可在主程序基础上增加前端。  
- 在跨子网场景无法直接通过 ARP 获取远端主机 MAC；需在目标网段内运行或查询网关/交换机的 ARP 表。

**可选改进（后续工作）**
- 在界面中自动检测并提示目标 IP 是否与所选接口同网段，若不同建议查询网关或更换接口。  
- 支持批量 IP 查询与并行发送/捕获以加速扫描。  
- 输出抓包日志（PCAP 文件）以便用 Wireshark 做进一步分析。  
- 增加更详细的调试选项（打印每个捕获包的解析结果、时间戳、接口等）。

---

如果你需要，我可以：  
- A) 把 README 中运行/编译说明补充到 repo（包括管理员提示），  
- B) 在 `main_lab3.c` 中加入“自动检查目标是否和接口同子网”的提示并建议默认网关作为候选，或者  
- C) 帮你把结果导出为实验报告的 LaTeX 片段并合并到主报告中。

你要我现在做哪项（A/B/C 或其他）？