# natwg

[English](README.md) | [简体中文](README.zh-CN.md)

即使家中网络位于运营商级 NAT（CGNAT）后，也能通过 WireGuard 从外网访问家中局域网。
natwg 持续保活公网 UDP 映射，并将端点发布到 DNS，让客户端在地址或端口变化后自动跟进。
无需中继或 VPS。

同一个程序可在 macOS 和 Linux 上充当服务端或客户端。WireGuard 通过
[gotatun](https://crates.io/crates/gotatun) 在进程内运行，无需另装守护进程。
服务端负责局域网路由、NAT 和 UPnP 端口租约。

## 网络要求

服务端需要可从外部访问的公网 IPv4 端点，或全锥形 NAT（NAT1）。
受限 NAT（NAT2、NAT3）、对称 NAT（NAT4）以及封锁 UDP 的网络无法运行 natwg 服务端。
运行 `natwg detect` 即可检测，无需 root 权限。

只有本机持有公网地址（`public_by: address`），或 UPnP 确认路由器的公网地址和端口转发
（`public_by: upnp`）时，才能发布 A 记录或使用原生 WireGuard 模式。
其余受支持的网络均使用 TXT，包括恰好保留监听端口的 NAT 映射。

## 安装

在两台设备上分别运行：

```sh
curl -fsSL https://natwg-dl.hackerchai.com/install.sh | bash
```

安装脚本校验压缩包的校验和及程序版本，然后安装到 `/usr/local/bin/natwg`。
预编译版本支持 Apple 芯片和 Intel Mac，以及 arm64 和 x86_64 Linux。
如果已有 Rust 1.99 或更新版本，也可以运行 `cargo install natwg --locked`。

## 连接第一台设备

在尚未配置 natwg 的服务端上，准备好 Cloudflare 域名区域，以及仅对该区域具有
Zone Read 和 DNS Edit 权限的 API 令牌。向导会检测网络，询问局域网和 DNS 设置，
为笔记本创建客户端身份，并启动服务：

```sh
sudo natwg init --mode natwg --peer laptop \
	--out /etc/natwg/clients/laptop.json --install-service
natwg status
```

等待状态显示隧道已启动，并且 TXT 端点或 A 记录已发布。
通过安全方式将 `/etc/natwg/clients/laptop.json` 传到客户端，保存为 `./laptop.json`。
文件内含客户端私钥。在客户端执行：

```sh
sudo install -d -o root -m 700 /etc/natwg
sudo test -e /etc/natwg/client.json || \
	sudo install -o root -m 600 ./laptop.json /etc/natwg/client.json
sudo natwg --config /etc/natwg/client.json service install
natwg status
ping -c 3 10.66.66.1
```

复制命令创建由 root 持有、权限为 0600 的配置，若文件已存在则保持不变。
若修改过服务端默认隧道地址，请相应修改 ping 的地址。近期握手记录和 ping 回复表明连接正常。
请妥善保留 JSON，以便日后导出，并删除传输副本。每台设备或每个应用都需要独立的客户端身份。

## 使用指南

以下详细文档为英文。

| 任务 | 文档 |
| --- | --- |
| 手动安装或指定版本 | [安装](docs/installation.md) |
| 理解检测结果和网络限制 | [网络检测](docs/network-detection.md) |
| 配置服务端或使用原生 WireGuard | [服务端设置](docs/server.md) |
| 编写 JSON 或修改隧道及局域网路由 | [配置参考](docs/configuration.md) · [网络调整](docs/configure.md) |
| 添加客户端、调整保活，或导出 Surge、mihomo 和 wg-quick 配置 | [客户端](docs/clients.md) |
| 升级程序或发布版本 | [更新](docs/updates.md) · [发布流程](docs/releasing.md) |

## 许可证

[MIT](LICENSE)
