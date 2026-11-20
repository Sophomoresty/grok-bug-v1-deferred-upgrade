# grok-play-deferred-upgrade

Google Play Billing **deferred subscription replacement** 机制研究副本: 在 Grok (ai.x.grok) 内先以 ~$9.99 订阅 `grok.lite`, 再通过 Play Billing RPC 的 `subscriptionProductReplacementParamsList` (replacement proto `m1.g(4)`, `replacementMode=3`, `oldSkuPurchaseToken` = lite 的 purchase token, `obfuscatedAccountId` 对齐) 触发 **deferred** 升级到 `grok.ultra` (SuperGrok Heavy) — 首扣被推迟到 lite 周期末, 随后 `cancelAtPeriodEnd`, 实现 "一付三" (lite 一次 ~$10 扣款, 获得 Heavy 到 lite 周期末 + ultra 周期)。

## 背景 (2026-08)

2026-08 我们逆向了市面 "Grok Heavy 谷歌内购" 渠道的机制并复现:

- 工具链: MuMu 模拟器 + Frida hook Play Billing (frida-java-bridge 注入, `g2 queryProductDetails` / `d2` 订阅替换参数 / `E()` plus sheet / IAB transact 902 ack)。
- 关键发现: Play Billing Library 7+ 把 deferred replacement 序列化进 `subscriptionProductReplacementParamsList` protobuf (混淆类 `t1`/`m1`/`o1`, `m1.g(modeArg)` = 4 对应 `DEFERRED` proration); 旧版 `c00.l4` binder 退路用 `R1`/`Q1`/`W1`。
- GID 对齐铁律: fromlite fire 的 `extras.accountId` 必须等于 lite 下单时 64-hex `obfuscatedAccountId` 的头 16 位, 否则 Subscribe 后 Acquire 返回 `item you requested is not available`。
- 升级单在 Grok 侧 GET 接口通常查不到 (drop), Play e2 inspect `grok.ultra autoRenewing=true` 才是成交真源; Cancel + IAB 902 ack 之后才能再 replacement (g4 写回)。

## 目录结构

```
README.md               本文件
LICENSE                 MIT
POST.md                 技术分享文章
skill/SKILL.md          机制向 runbook: lite -> fromlite(deferred) -> Cancel+ack -> g4 写回链路, 16 闸有人值守
scripts/fire_heavy.py   Frida dispatcher: attach Grok 进程, 调 hook 的 rpc exports (inspect/p1m/fromlite/g4/...)
scripts/billing_core.py 机制函数: frida fire 流程, hook 编译与 GID/token 注入, 墙分类判定, Cancel/ack, buy_lite/buy_fromlite/buy_g4
scripts/gate_attended.py 有人值守闸 CLI: shot / lite-wall / fromlite-wall / sub (截图 -> 人确认 -> Subscribe tap)
scripts/xai_oracle.py   xAI 侧状态核验脚本 (查 GET /rest/subscriptions 确认订阅是否落地)
hooks/package.json      frida-java-bridge 依赖声明 (编译前在 hooks/ 执行 npm install)
hooks/lite_wall.js      grok.lite 下单 hook (g2 offers -> d2 accountId=GID)
hooks/heavy_wall.js     grok.ultra hook (inspect / fromlite deferred replacement / g4 写回 / ack902)
hooks/dump_gid.js       从 Grok app 内存 dump 64-hex Google obfuscated id (R8 混淆退路 bg0.r1)
hooks/ack_27008.js      IAB binder transact 902 acknowledgePurchase 模板
```

## 使用前提 (自备)

本仓库是**脱敏研究副本**: 不含任何账号 / 卡 / 代理 / 设备实例信息, 也不保证开箱即跑。复现需要读者自备:

- MuMu (或任意 root adb 可达的 Android x86 模拟器) + 设备 serial, 通过 `MUMU_SERIAL` 环境变量传入 (如 `MUMU_SERIAL=127.0.0.1:16384`)
- `adb` (在 PATH), `adb shell` 已是 root
- Frida: 设备侧 `frida-server` (放 `/data/local/tmp/frida-server`), 主机侧 `frida` python 包 (`uv run --with frida-tools` 即可) 与 `frida-compile` (先在 `hooks/` 下执行 `npm install` 安装 `frida-java-bridge`, 再编译 `hooks/*.js` 到 `./work/hooks/*.compiled.js`)
- `tesseract` (FLAG_SECURE 墙 OCR 判定)
- 自备的 Google 账号 (密码经 `GOOGLE_PW` 环境变量传给 verify 流程), 自备付款方式 (last4 经 `CARD_LAST4` 环境变量/CLI 参数传给墙选卡判定), 自备美国出口网络 (`US_EGRESS`; egress/DNS 钉死逻辑已移除)
- Grok app 版本: 验证于 1.2.46 (Play Billing 9.1.x, GMS play_billing 1218/1246)

## 免责声明

- 本仓库仅供 Google Play Billing 机制研究与学习, 展示 deferred replacement 参数如何构造与判定。
- 已脱敏: 不含任何账号, 卡号/BIN, 代理/节点, 个人路径, 库存/交付信息。
- 请遵守 Google Play 开发者政策与当地法律; 对使用本仓库代码造成的任何后果自负。

## 系列

- v1 本仓库: Lite 一付三 deferred replacement (2026-08)
- v2 `grok-play-leftover-writeback`: 停续 leftover 的 $0 写回 (2026-09)
- v3 `grok-play-leftover-hop`: skipg4/destg4, leftover 跨账号转移 (2026-09)
- v4 `grok-x-subscription-ultra`: 新 SKU mode3 换购 + 墙分类 (2026-10)
