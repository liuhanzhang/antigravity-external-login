# Antigravity External Login

通过本机 macOS 钥匙串保存 Google 登录凭据，并在启动 Antigravity 时恢复凭据、临时跳过地区限制页面。应用安装包和 `language_server` 不作修改。

## 环境

- macOS Apple Silicon。
- Antigravity 安装在 `/Applications/Antigravity.app`。
- Python 3.9+、Node.js 22+、Xcode Command Line Tools（提供 `swiftc` 和 `llvm-objdump`）。

已验证的应用版本为 2.33.0。脚本按安装包结构识别配置，不按应用版本号锁定；结构不匹配时会停止。服务端资格检查仍可能返回 `ineligible`，页面处理不改变该结果。

## 使用

在仓库目录中检查安装环境：

```sh
python3 antigravity-external-login.py check
```

首次在这台电脑使用时完成一次 Google 登录：

```sh
python3 antigravity-external-login.py login
```

在浏览器选择自己的 Google 账号完成登录。若默认浏览器资料不合适，用 `login --no-browser` 显示本机链接，再在需要的浏览器资料中打开。已有外挂凭据的电脑可直接使用 `start`。

以后先正常退出 Antigravity，再运行：

```sh
python3 antigravity-external-login.py start
```

启动器会刷新凭据、备份并更新原生钥匙串条目、带本机调试参数启动原版，然后运行页面脚本。应用已运行时，启动器会停止。

若终端不能读取 `Documents`，将整个仓库放在其他目录，例如 `~/personal` 或 `~/.local/share`。换电脑时复制源码并在新设备重新登录。

## 命令

| 命令 | 行为 |
| --- | --- |
| `check` | 检查安装包结构及外挂凭据条目是否存在，不输出凭据 |
| `login` | Google OAuth 登录，验证刷新后存入本机钥匙串 |
| `provide` | 刷新并提供原生凭据，不启动或退出应用 |
| `start` | 提供凭据、启动原版、跳过地区限制页面 |

页面脚本也可以单独使用。应用需带调试参数启动、停在限制页面，并已持有登录令牌：

```sh
open -a Antigravity --args --remote-debugging-port=0
node antigravity-skip-region-page.mjs --check
node antigravity-skip-region-page.mjs
```

## 文件与凭据

- `antigravity-external-login.py`：唯一的工具入口，包含安装包配置识别、登录和启动流程。
- `external-keychain.swift`：原生钥匙串接口，首次需要时编译到被 Git 忽略的 `.build/`。
- `antigravity-skip-region-page.mjs`：通过本机调试端口临时处理前端页面。

源码不含用户令牌或从安装包提取的客户端配置。OAuth 配置只在运行时从本机安装包读取。OAuth 使用 PKCE 和本机回环回调，参考 [Google 桌面应用 OAuth 文档](https://developers.google.com/identity/protocols/oauth2/native-app)。

外挂凭据存放在钥匙串服务 `Antigravity External Login` 的 `oauth` 条目。原版使用服务 `gemini`、账号 `antigravity`；每次覆盖前，会在外挂服务中保存名称以 `native-keyring-backup-` 开头的原值备份。凭据通过进程标准输入传给 helper，程序不会将其写入源码、命令行参数或普通日志。

停止使用启动器即可停止外挂启动流程。在原版中可正常退出登录；外挂保存的凭据与备份可在“钥匙串访问”中管理。

## 验证与兼容性

在 Antigravity 2.33.0 上已验证 Google 登录与刷新、原版重启恢复、标记访问令牌过期后再次启动，以及 Gemini 4 Hydrogen High 在无项目会话中返回 `OK`。

仓库整理时可运行以下本机检查；它们不执行登录、刷新、钥匙串写入或重启：

```sh
python3 antigravity-external-login.py check
python3 -m py_compile antigravity-external-login.py
node --check antigravity-skip-region-page.mjs
swiftc -typecheck external-keychain.swift
```

应用更新后，原生函数表、OAuth 配置结构或前端流程变化均可能需要适配。编译产物和缓存不纳入 Git。
