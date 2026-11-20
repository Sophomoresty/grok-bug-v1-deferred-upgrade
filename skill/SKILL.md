# grok-play-deferred-upgrade (mechanism runbook)

Play Billing deferred replacement "一付三" 的机制向 runbook. 由原 skill 的 fast-path / attended-heavy / lite-g4-writeback 提炼, 只保留机制; 库存/交付/卡/代理段已删除.

设备/网络约定 (脱敏后):

- 模拟器 serial: 环境变量 `MUMU_SERIAL` (adb 可达即可), `ADB_SERVER_SOCKET` 按需.
- 网络: 自备美国出口 (`US_EGRESS`); egress/DNS 钉死逻辑不在本仓库.
- Google 密码: `GOOGLE_PW`; 付款方式 last4: `CARD_LAST4`.
- 工作目录: `./work/` (hook 编译产物, 截图, fire 证据).

## 一句话机制

空库 Grok 账号先订 `grok.lite` (~$9.99 Today), 同一 session 用 Billing `d2` 携带 deferred replacement 参数 (`subscriptionProductReplacementParamsList`, `m1.g(4)`, `replacementMode=3`, `oldSkuPurchaseToken`=lite token, `accountId`=GID 头 16) 触发 `grok.ultra` 升级墙 (无 Today $, "Your first charge will occur on <lite 周期末>"), 人审后 Subscribe → ultra `autoRenewing=true`; 之后 sku manage URL Cancel + IAB 902 ack, 再一发 g4 replacement 写回新 GPA ($0 today), 再 Cancel 到 `cancelAtPeriodEnd`. 结果: 一次 ~$10 扣款, Heavy 权益覆盖两个周期 ("一付三" 口径).

## 链路总览 (16 闸, 全程有人值守)

| 闸 | 内容 | 关键判定 |
|---|---|---|
| 1 | 设备/网络 up, US 出口 | Play uid egress `US` |
| 2 | Google 账号登录进设备 | `dumpsys account` 只有目标账号 |
| 3 | Grok app 登录 (自备账号注入) | `device.grok_accounts()` 是目标账号 |
| 4 | TOS Accept | 精确 `Accept & Continue` cy~1681, 禁止 Sign out (~1819) |
| 5 | GID dump | `dump_gid` 64-hex; 空 Play 库必须 `allow_vending=False` |
| 6 | `prepare_hooks(GID)` 编译 lite/heavy hook | `var GID` 已注入 compiled js |
| 7 | 付款方式检查 | dump Payment methods; 空库才继续 |
| 8 | Lite 墙 HOLD: `gate_attended.py lite-wall` | 墙必须 `SuperGrok Lite` + `Starting today $9.99` |
| 9 | 人看截图 → `gate_attended.py sub` → 立刻 inspect | `grok.lite autoRenewing=true` 才算付成 |
| 10 | 离开 Play 账单页回 Grok Ask; fromlite 墙 HOLD | 无 Today $, 有 first charge; `offerId=regular-p1m`, `accountId==GID头16`, `modeArg=4` |
| 11 | 人看截图 → `sub` → 立刻 inspect | `grok.ultra autoRenewing=true` |
| 12 | Cancel: sku manage URL, 右侧 Cancel `786,1857` | 订阅页 `Canceled` + `will end on`, AR=false |
| 13 | `ack_token` (IAB 902) | 不 ack 则后续 replacement 报 `unable to change` |
| 14 | g4 写回墙 HOLD: force-stop Grok → Ask 无 IME → `buy_g4` | overlay 在 Manage dimmed 上, 无 Today $, 人审 → `sub` |
| 15 | poll inspect 直到**新 GPA** AR=true | 不要把 leftover 旧 GPA 当成功 |
| 16 | 再 Cancel 到 `cancelAtPeriodEnd` | AR=false + cap |

升级三次 Subscribe (Lite / fromlite / g4) 都是人看完当次截图再点一次 (`GROK_HOLD_SUBSCRIBE=1`), 禁止无人代订.

## Lite 墙 (闸 8-9)

- `fire('p1m')` 必须挂 **lite_wall** hook (heavy hook 打出来是 Ultra Today $299, 禁订).
- 墙判定 `gate_lite`: `SuperGrok Lite` + `Starting today $9.99` (`lite_today`); `99.99/299.99` = `CHARGE_FULL` BACK; `Start by adding a payment method` = `need_bind` (从墙里 Add card, 不要 BACK).
- Subscribe 坐标 `su_tap(540,1836)` (1810 clamp 点不到; OCR "by tapping Subscribe" 是文案不是按钮).
- Play 要密码: AdbIME 填 `GOOGLE_PW`, `su_tap(540,1836)` Verify; FLAG_SECURE dump ~14KB OCR 空 = 密码页, 直接 type+Verify `540,1435` / `540,1785`.
- Subscribe 后立刻 inspect; `timeout_continue` 不是已付, 只有 inspect `grok.lite AR=true` (或 OCR `Payment successful`) 才算.
- Lite 已付后 backup 弹窗 (`Turn on backup payment methods?`): **禁止 Turn on**, BACK. (Turn on 后立即 fromlite 曾出 item.)

## fromlite (闸 10-11, 核心)

前置:

- inspect 必须有 `grok.lite` token (AR=true).
- 必须离开 Play 账单页 (Payment methods / backup / Payments & subscriptions 枢纽), 回到 Grok `Ask anything`; `leave_play_for_fromlite` 处理 TOS `Accept & Continue` 540,1681.
- `refresh_fromlite_hook` 用**当次 lite 收据**重新 compile hook (`prepare_hooks(receipt obf, lite_token)`): hook 烘焙早于 Lite 会导致 Subscribe item; 已知 lite-gid16 时收据 obf 头 16 不一致 → `receipt_gid_mismatch` fail-closed 不订.

fire 判定 (全过才允许走到墙):

- `offerId == "regular-p1m"` (`fromlite_offer_ok`); p3m / intro offer 的墙 Subscribe 必 item.
- `accountId == lite GID 头 16` (`fromlite_account_ok`), 且与 hook `var GID` 一致; 收据 obf 可以与 lite 下单 GID 不同 (实测有 5d90 vs 6b2e 案例), 用收据 obf 去 replace 会 item — 所以以 live 收据重编译.
- `modeArg == 4` (proto `m1.g(4)` = deferred; modeArg 3 = 立即按比例扣, 禁止).

墙判定 `gate_heavy` / `wall_is_ready`:

- 通过 = SuperGrok Heavy overlay 在 Grok 上, **无 Today $**, 有 `Your first charge will occur on …` (`FIRST_RE`), `first charge <lite 周期末>`.
- `Starting today $` / Today $99 / $299 → `CHARGE_FULL` BACK.
- `Starting Oct 25 $99.99` intro 墙 (`oct25_item_wall`) → Subscribe 必 item, BACK.
- `unable to change your subscription plan` → 先 ack 再试, 当次禁止再 fire.
- **fire JSON 全对但 wait_wall 是 `Payments & subscriptions` / Payment methods 枢纽** (`fromlite_landed_play_hub`): replace 已被第一次落页消耗, **禁止再 fire / 禁止 Subscribe / 禁止 force-stop 再出墙** (重发出的是幽灵 deferred 墙, Subscribe 必 item).
- 转圈页 (`android:id/progress` ProgressBar) 不是墙, 继续等, 不要把 OCR 垃圾当 unknown 后 force-stop.
- FLAG_SECURE 第一次 dump 空是常态, 再 dump; 选卡 `pick_wall_card(CARD_LAST4)` fail-closed, 墙上出现别的 last4 = `wrong_card` 不订.

## Cancel + ack (闸 12-13)

- Cancel 走 sku manage URL: `https://play.google.com/store/account/subscriptions?sku=grok.ultra&package=ai.x.grok` (点列表里的 SuperGrok 会 deep-link 进 Grok, 永远见不到 Cancel).
- 右侧 Cancel 药丸中心 `786,1857` (OCR 常把 Pause payments / Cancel subscription 连读, 落在两按钮间隙; 左侧是 Pause, 禁止点).
- 确认页右侧蓝 Cancel; Play Points overlay 点 `Not now`; Grok TOS 盖在上面时先点 `Accept & Continue` 540,1681.
- 等 `Canceled` + `will end on …`, inspect `autoRenewing=false`.
- `ack_token(purchaseToken)`: IAB binder `transact(902)` acknowledgePurchase. 不 ack 直接 g4 → `unable to change your subscription plan`, 盲等无效.

## g4 写回 (闸 14-16)

- ack 完 BACK 离开 Manage; `am force-stop ai.x.grok` 再 `am start` Grok, 收 IME, 截图确认 Ask `Try SuperGrok` 无 IME 再 fire.
- `buy_g4`: 先自查 `grok.ultra AR != true` (AR=true 时返回 `g4_still_renewing` 不发), token 存在则先 ack.
- g4 墙判定同 fromlite (deferred, 无 Today $). 第一发落 **Manage Canceled 无 overlay** (`g4_gate`): 禁止 Subscribe / 禁止点 Resubscribe; force-stop 后从 Ask 再发一次, overlay 出现 (dump ~30KB 级) 才 HOLD.
- 人审: SuperGrok Heavy overlay, first charge, `regular-p1m`, mode 4, 正确 last4, 无 Today $ → `sub`.
- poll inspect 直到**新 GPA** (≠ fromlite 旧 GPA) `AR=true`, 再 `cancel_grok` cap 到 `cancelAtPeriodEnd`.

## 已知失败模式 (机制侧)

| 现象 | 含义 | 动作 |
|---|---|---|
| Subscribe 后 `The item you requested is not available` | 这笔 offer/replace 对当前 Play 账号不可买 (ITEM_UNAVAILABLE), 不是扣款失败 | `accountId` 不对 → 重编译 hook; GID 已齐 → 本号放弃 fromlite, 不 cancel Lite |
| `unable to change your subscription plan` | 旧单未 ack / 仍 AR=true | 先 `ack_token`, AR=false 再 fire |
| `Turn on backup payment methods?` 卡 40s | backup 弹窗 | Lite 未付完: No thanks; 已付: BACK |
| fromlite 落 Play 枢纽无 overlay | replace 已消耗 | 停, 禁止再 fire (幽灵墙 item) |
| 空库直接 p3m/p1m Heavy | `Starting today $99.99/$299.99` | BACK, 禁订 (空库不能 $0) |
| dump 0 字节 | FLAG_SECURE / uiautomator 饿死 | OCR 代替循环 dump; 空 dump ≠ 墙已离开 |

## 单闸命令 (机制核心)

```
export MUMU_SERIAL=127.0.0.1:16384          # 自备模拟器
export GROK_HOLD_SUBSCRIBE=1
export GOOGLE_PW=... CARD_LAST4=...         # 自备

frida-compile hooks/lite_wall.js  -o work/hooks/lite_wall.compiled.js
frida-compile hooks/heavy_wall.js -o work/hooks/heavy_wall.compiled.js

python3 scripts/gate_attended.py shot                          # 截图+dump+分类
python3 scripts/gate_attended.py lite-wall  --hook work/hooks/lite_wall.compiled.js --last4 $CARD_LAST4
python3 scripts/gate_attended.py sub                          # 人审截图后点 Subscribe
python3 scripts/gate_attended.py fromlite-wall --hook work/hooks/heavy_wall.compiled.js --last4 $CARD_LAST4
python3 -c "import sys; sys.path.insert(0,'scripts'); import billing_core as b; \
  print(b.inspect()); print(b.cancel_grok()); \
  print(b.ack_token(<ultra purchaseToken>, work_dir))"        # Cancel + 902 ack
# g4 写回: HOLD buy_g4 同 fromlite 流程
```

fire dispatcher 也可单发: `python3 scripts/fire_heavy.py inspect|p1m|fromlite|g4` (hook 由 `HOOK_JS` 指定).
