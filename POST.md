# 逆向市面 228 的 Grok Heavy 谷歌内购, 用 Play replacement 参数复现 "一付三"

8 月底买了三只市面的 Grok Heavy 号 (两个 228 非速刷, 一个 88 速刷), 只读对齐指纹之后, 把它的 Google Play 计费链完整逆向复现了一遍: 付一个月 Lite 的钱 (~$10), 用 Billing 的订阅替换参数把订阅换成 Heavy (grok.ultra), 首扣被推迟到 Lite 周期末, 再立刻停续 — 实付 ~$10 拿三个月 Heavy. 文末有脱敏工具仓库. 文里略去了具体账号和卡信息.

## 0x00 背景: 三只号的共同指纹

先用 SSO JWT 打 xAI 的只读 gRPC (GetUser / GetSubscriptions / GetGoogleObfuscatedId / ListActiveSessions), 三只号对齐下来共同点非常整齐:

- 全部 EmailPassword 登录, 无 Google OAuth, 无 MFA
- 只有 `grok.ultra` p1m 单, 0 条 `grok.lite`
- `obfuscatedAccountId` 是服务器签发的 64-hex, 不是 userId
- Play 侧周期起点贴着甚至**早于** xAI 建号时间 (速刷那只早了 99 小时 — 先有 Play 账期, 再建号 attach)

结论: 货源走的是 Google Play 内购链, 不是 Stripe, 也不是网页兑换码. 那问题就变成: Play 上怎么把 $99.99/月的 Heavy 卖到 228 (约 $30 三个月)?

## 0x01 环境

- macOS + MuMu 模拟器 (后来也验过真机 Pixel), adb 接上
- Grok app (jadx 反编译看 Acquire 链), Play 商店正常登录, 一张限额虚拟卡
- hook 用的 Frida. Magisk 方案在这条链上不稳, 直接 Frida attach 进程最省事

```bash
adb connect 127.0.0.1:16384
frida -U -n Grok -l heavy_wall.js
```

## 0x02 逆向: 一路否证

jadx 里订阅入口是 `szx.a` → `xyu.D` (sku → docid) → `portrait.UI_BUILDER / phoenix.ACQUIRE`. 把可疑点挨个试过去, 全是否证:

| 假设 | 结果 |
|---|---|
| 跨 SKU 传 token (pro 的 token 买 ultra) | 目录价不变 |
| `enablePendingPurchaseForSubscriptions` | 无效果 |
| `SKU_OFFER_TYPE_LIST=18` 强改 offer 类型 | 墙仍目录价 |
| Instrumentation 改运行时字段 `swe.f` 为 pro 的 $29.99 token | 墙仍 Heavy $99.99, 价不在这个字段 |
| `additionalSkus` 混单 | 直接加价 |

价格不在客户端任何一个可改字段里. 把视线移到 Billing RPC 的 extras 上.

## 0x03 活路径: subscriptionProductReplacementParamsList

关键在 Play Billing AIDL `getBuyIntent` (d2) 的 extras: 不带 `oldSkuPurchaseToken` 时它是一张全款墙; 带上 "拿一张已有订阅替换" 的参数后, Play 会按**替换规则**计价 — 首扣推迟到被替换单的周期末. 这就是 deferred replacement.

hook 里构造的 proto (play_billing 内部类 `t1/m1/o1`):

```js
function putReplaceProto(extras, AL, oldSku, newSku, modeArg) {
  var t1 = Java.use('com.google.android.gms.internal.play_billing.t1');
  var m1c = Java.use('com.google.android.gms.internal.play_billing.m1');
  var o1c = Java.use('com.google.android.gms.internal.play_billing.o1');
  var newB = t1.p();
  newB.e('subs:ai.x.grok:' + newSku);        // grok.ultra
  var oldB = t1.p();
  oldB.e('subs:ai.x.grok:' + oldSku);        // grok.lite
  var lb = m1c.p();
  lb.e(newB);
  lb.f(oldB);
  lb.g(modeArg);                              // replacement mode
  var ral = Java.use('java.util.ArrayList').$new();
  ral.add(lb.a());
  var ob = o1c.p();
  ob.e(ral);
  extras.putByteArray('subscriptionProductReplacementParamsList', ob.a().b());
}
```

d2 的完整 extras (能出 deferred 墙的最小集):

```js
ex.putString('oldSkuPurchaseToken', replace.token);   // Lite 单的 purchaseToken
ex.putStringArrayList('skusToReplace', ['grok.lite']);
ex.putInt('replacementMode', 3);                       // WITHOUT_PRORATION 家族
ex.putString('accountId', gid);                        // 对齐 obfuscatedAccountId
// + subscriptionProductReplacementParamsList 见上
var bb = fd.d2(17, PKG, 'grok.ultra', 'subs', ex);
```

所以完整链路是: 先正常买一个月 `grok.lite` (~$10 实扣), 再用它的 token 做 oldSku 发起替换 → 墙上 Heavy 没有 "Starting today $99.99", 只有 "首扣将于 X 日" — Lite 周期末. Subscribe 之后 Play 库里 `grok.ultra` 生效, lite 被替换. 最后一步, 在 app 里把订阅停续 (cancelAtPeriodEnd), 周期末的 $99 就不会扣. **一付三**: $10 出头, 三个月 Heavy.

## 0x04 踩坑

- **unable to change your subscription plan**: oldSku 那张单如果是 un-acked 状态, 替换直接被拒. 先对 oldSku transact 902 补 acknowledge 再 fire.
- **obfuscatedAccountId 不对齐**: extras 的 `accountId` 必须和收据上的 obf 一致, 传 userId 进去 xAI 侧不认, GET 就是空.
- **FLAG_SECURE**: 支付墙禁止截屏 dump, uiautomator 经常给空 XML, 逼着全程 OCR 判墙.
- **already owned**: Play 库里已有同 SKU 时墙都出不来, 先 `getPurchases` (e2) inspect 再动手.
- **Play 报 "No internet"**: 模拟器 DNS 抽风, 挂美国出口重试就好, 跟账号无关.

## 0x05 终态验证

以 xAI 侧为准, 不以 Play 界面为准:

```
GET /rest/subscriptions?includeInactive=true
→ grok.ultra STATUS_ACTIVE, cancelAtPeriodEnd=true
```

REST 被 Cloudflare 挡的话, 用设备 uid 直发 gRPC `GetSubscriptions` (空请求), 同一个 JWT 能拿到同样的行. 两条路都空才是真空.

## 0x06 工具

脱敏后的 hook 与驱动在 GitHub: `grok-play-deferred-upgrade` (private, 审完后公开, 链接补在这).

下一篇 (leftover $0 写回) 会讲怎么把 "$10 的一次 Lite" 也省掉.

仅供 Play Billing 计费机制研究, 请勿用于非自有账号.
