# 逆向市面 228 的 Grok Heavy 谷歌内购: 用 Play 的订阅替换参数复现 "一付三"

8 月底买了三只市面的 Grok Heavy 号(两个 228 非速刷, 一个 88 速刷), 只读对齐指纹之后, 把它的 Google Play 计费链完整逆向复现了一遍: 付一个月 Lite 的钱(~$10), 用 Billing 的订阅替换参数把订阅换成 Heavy(grok.ultra), 首扣被推迟到 Lite 周期末, 再立刻停续--实付 $11 出头拿近一个月 Heavy 到期, 加上写回玩法实际吃到三个月档期. 中间否证了十几条路径, 撞过一次 "像 248 的墙" 的空欢喜, 最后一击才落在 replacementMode 上. 文里略去了具体账号和卡信息.

## 0x00 三只号的指纹: 货是 Play 链做的

先说怎么确认渠道. REST 的 `/rest/subscriptions` 直接被 Cloudflare 403, 所以全部走只读 gRPC 五件套: GetUser / ListLinkedAccounts / GetGoogleObfuscatedId / GetSubscriptions(空请求)/ ListActiveSessions. 三只号对下来:

| 号 | 渠道价 | ultra/lite | 停续 | 关键时间线 |
|---|---|---|---|---|
| 卖家A | 228 | 1 条 ultra, 0 lite | cap=true, lastModified=create+21s | Play 周期锚比 xAI 建行早 ~50s |
| 卖家B | 228 | **3 条 ultra**, 0 lite(2 条同分钟 INACTIVE) | autoRenew, 不停 | 周期锚比 ACTIVE 建行早 375s; 注册台北, 订购 +104s 出现纽约会话 |
| 卖家C | 88 | 1 条 ultra, 剩余 26.87 天 | autoRenew | Play 周期起点 08-25,**比这个 xAI 用户的创建时间(08-26)还早**, xAI 建行再晚 99h |

几个推理从这里直接掉出来:

- 三号全部 EmailPassword 登录, 无 Google OAuth, 无 MFA → 不是 OAuth 同步链.
- 反编译看了一圈: xAI 客户端的订阅写口只有 `CreateBillingPortalSession / CreateStripeCustomer / SubscribeViaStripe`,**没有** ReportGoogle 之类的客户端上报 → Play 单只能走 Google 的 RTDN 后端通知, 不能伪造.
- GetProductsInfo 里 Stripe 的 Heavy 是 prod_Sdnv8D1IKHvyAs, $300/月, $3000/年; Apple 只有 supergrok.pro.monthly.300; Google 目录的 grok.ultra 没标价 → 88/228 的价格不在 xAI 任何目录里, 必然来自 Play 侧.
- 卖家B 那 2 条同分钟 INACTIVE 是直充失败重试的残骸; 卖家C 的 88 更有意思: 88/228 ≈ 0.39, 但 26.87/31 ≈ 0.87,**不是按剩余天数线性定价**--它是 "先在 Google 账本上囤好 grok.ultra 账期, 再建 xAI 号把 GID 烙上去" 的速刷工艺, 账期起点早于账号存在本身. 三只号是三种不同工艺, 不是单一工厂.

## 0x01 环境: 0 消耗的试错纪律

MuMu 模拟器(adb 接 16384 这类本地口)+ 真机 Pixel 各一台, Grok app 1.2.18(BillingClient 9.1.0), Play Store 活体 52.9.21(注意: jadx 参考的是 52.8.55, 符号和活体对不上, 后面踩坑细说), Frida 17 挂进程. 卡里只放 $11--和真扣 $99.99 比, 让银行拒掉比任何心理安慰都管用.

最重要的一条纪律:**试错全程 0 消耗**. hook IInAppBillingService 的 transact, 只调 d2(getBuyIntent, api=17)拿 BUY_INTENT 不 send; 或者 send 弹墙后只 dump 布局再 BACK, 绝不点 Confirm. 一天喷了几十个参数组合, 实扣为零.

## 0x02 jadx: 购买链长什么样

Grok 侧: 订阅按钮 → `j9.z` → `GetGoogleObfuscatedId`(空请求, 当前 SSO; 返回**服务器签发**的 64-hex, 不是 userId, 也不是任何本地哈希--uid/去连字符/大写/email 全试过, 都不等于签发值)→ `h9.i.x(offer, obf, 当前google订阅)` → `launchBillingFlow` → d2 的 extras 里 accountId=obf, oldSkuPurchaseToken=当前订阅 token.

Play 侧: `szx.a` 构造 GetBuyIntentParams, `xyu.z` 把 sku 编成 docid(`subs:ai.x.grok:grok.ultra`), `xyu.D` 建购买文档出 BUY_INTENT; 本地校验 `xux.H` 只查列表等长,**不查 offerToken 归属**. 弹出来的那张 "墙" 本体是 `https://play-fe.googleapis.com/fdfe/ees/acquire?theme=2` 的 HTTP 响应(body protobuf 类 byvr); 价格本身在 g2(skuDetails)的 JSON 里, 不在 byvr 信封里--这两个定位决定了后面所有改价尝试的失败命运.

## 0x03 否证: 一路喷过去

按 "价格可能在哪" 的顺序试, 每条都是 操作 → 返回 → 结论:

| 假设 | 做法 | 返回 | 结论 |
|---|---|---|---|
| 跨 SKU 塞 token | 拿 grok.pro 的 intro token 配 ultra 的 sku 发 d2 | **d2rc=0 签出了 BUY_INTENT**, 墙却弹 "Subscription not available" | d2rc=0 只是签了 PendingIntent, 价和可买性在 Acquire 服务端判,**d2rc 不是 oracle** |
| 换商品文档 | SKU_SERIALIZED_DOCID_LIST 塞 pro 的文档 | 墙变成 "SuperGrok Today 3-month $29.99"--**最像 248 的一次** | serializedDocid 覆盖的是商品身份: 那是 pro 的正版 $29.99×3 月 offer, 不是 Heavy 打折, 点进去买到的也不是 Heavy |
| 试用类型 | SKU_OFFER_TYPE_LIST=18(TRY_BEFORE_YOU_BUY) | dump 证实 t=18 已写进 acquire 参数, 墙仍 $99.99 | 服务端不吃客户端的 ccwy |
| 改运行时字段 | Instrumentation 改 swe.f 为 pro 的 $29.99 token | 墙仍 "Starting today $99.99/month" | 价不读这个客户端字符串 |
| 混单 | additionalSkus=[grok.pro] | "Today $129.98 = $99.99+$29.99", 诚实求和 | 没有合并优惠这种东西 |
| 改 UI 价 | TextView.setText / JSONObject.put 改 $99.99→$29.99 / 改 acquire 缓存 gzip | 缓存那条最唬人: 墙稳定显示 $29.99/month×3 | 全是 display-only, 服务端 skuDetails 仍是 $99.99, Confirm 走的是真价 |

## 0x04 对照实验: ReplacementMode 全矩阵

真正的突破来自换一个问法: 不改价, 改**计价规则**. Billing 有一组 "订阅替换" 参数(protobuf 类 m1/t1/o1, 枚举构造器 l1.g(n)), 同一个 oldSku(一张已取消的 ultra)从 g(2) 到 g(7) 全喷一遍:

| 构造 | zzg 枚举 | 墙上原文 |
|---|---|---|
| g(4) | 3 WITHOUT_PRORATION | "SuperGrok Heavy Starting Sep 29 $99.99/month",**无 Starting today 行, 首扣 Sep 29** |
| g(6) | 5 CHARGE_FULL | "Today $99.99 + 57 days (includes 27 days converted from the remaining time on your current plan)" |
| g(3) / g(7) / g(2) | 2 / 6 / 1 | "Something went wrong on our end. Please try again." |

答案很清楚了:**目录价 $99.99 没变, 变的是首扣日期**. WITHOUT_PRORATION 的替换会把新单首扣推迟到被替换单的周期末--这就是 "一付三" 的引擎. 顺带一提 g() 入参和枚举值差 1(g(4)→zzg=3), 第一次对调 proto 的 field1/field2 直接 DF-DFERH-01, 顺序也是踩出来的.

## 0x05 复现: 从 $10 的 Lite 到 0 元的 Heavy

完整链路(hook 里的 sendBuy):

```js
ex.putString('oldSkuPurchaseToken', liteToken);      // 活 Lite 单的 token
ex.putStringArrayList('skusToReplace', ['grok.lite']);
ex.putInt('replacementMode', 3);
ex.putString('accountId', liteReceiptObf);           // 必须 == Lite 收据上的 obfuscatedAccountId
// proto: t1.p().e('subs:ai.x.grok:grok.ultra') 新, t1.p().e('...grok.lite') 旧,
// m1: lb.e(newB).f(oldB).g(4) → zzg=3, o1 包一层 →
ex.putByteArray('subscriptionProductReplacementParamsList', bytes);
var bb = fd.d2(17, 'ai.x.grok', 'grok.ultra', 'subs', ex);
bb.getParcelable('BUY_INTENT').send();               // 拉起墙
```

墙上出现 "SuperGrok Heavy / Starting Sep 30 $99.99/month / first charge Sep 30"(Sep 30 正是 Lite 周期末)且**没有 Starting today**, 才点 Subscribe. 点完 Play 库里 lite 行消失, 只剩 `subs:ai.x.grok:grok.ultra` 的新 GPA, 当日实扣 **$0**. 紧接着订阅页 Cancel → cancelAtPeriodEnd, 周期末那笔 $99.99 永远不会发生.

端到端那只号: Lite 首购 $9.99 还被风控 hold 了两个半小时(模拟器+DC IP+虚拟卡的画像, Play 显示 "Confirm plan before Sep 4"), RTDN 自己落地后链路才通; 升级墙 "Starting Oct 1, 2026 $299.99/month. Your first charge will occur on Oct 1", Confirm 后今日 $0, app 立刻显示 Heavy.**总成本 $9.99+税=$11.04 ≈ 79 块**, 市面卖 228.

一个必须交代的阴影: 那张 $0 的升级单在 xAI 侧的 RTDN 迟迟不落(16h+). d2 nudge / ack / 深链 / REST sync / 六个 receipt 端点全试了, 不是 404 就是无效. Play 侧的单永远成立, 但 xAI 侧这条链在那个时间窗之后就没再复现过--大概率服务端对 "$0 deferred vs $299.99 目录价" 加了校验. 所以这篇文章讲的是机制考古, 不是可用的省钱教程.

## 0x06 踩坑实录

- **"Developer hasn't acknowledged your purchase"**: Subscribe 后不 ack, 后续所有计划变更墙都被这句挡住. 以为是 proto 构造错了, 折腾半天, 其实是 transact 902(writeInterfaceToken → writeInt 9 → pkg → token → Bundle)没跑.
- **obfuscatedAccountId 不是 userId**: 拿 userId 或邮箱哈希塞 accountId, 墙能出但 xAI 侧 GET 永远空. 它是 GetGoogleObfuscatedId 服务器签发的, 必须登录态现调.
- **e2 绑账号不绑 UI**: Play 界面切了新号, d2 仍返回旧号的库. 以为切号成功, 其实 getPurchases 跟着账号走, REMOVE+ADD 才算切.
- **JADX 名 ≠ 活体名**: hook 按 52.8.55 的符号写, 活体 52.9.21 里类根本不存在(活 d2 是 xsi.H, acquire proto 是 cbhb 不是 cbbp). 教训: 每次先 classdump 再 hook.
- **Frida 在 vending 上的崩溃族**: 新鲜 Play 进程立刻 attach 必 SIGSEGV(先无 hook 开一次墙再挂); Java.array / Module.findExportByName 在这个 bundle 里 "not a function"; hook 全量 Activity 回调会把 Cronet 打进解释器然后崩.
- **FLAG_SECURE**: 支付页禁止截屏, uiautomator dump 经常 0 字节, 判墙全靠 screencap+OCR.
- **recovery_mode 陷阱**: vending 崩溃后 `:recovery_mode` 进程残留, BUY_INTENT 全部进 "Google Play Store is updating". kill 掉再把 `files/recovery_state_` 写回 NONE(30 字节)才恢复.

## 0x07 帐

| 路线 | 成本 | 产出 |
|---|---|---|
| 市面 228 | 228 RMB | 金标/速刷号一只, 工艺不可控 |
| 自复现一付三 | $11.04 | Play 侧 $0 Heavy 单 + 周期末停续 |
| 市面 88 | 88 RMB | 剩 26.87 天的速刷, 且三天后掉号(Play 单被撤, 1 分钟内 3 次重试全灭) |

## 0x08 工具

脱敏后的 hook 与驱动在 GitHub: `grok-play-deferred-upgrade`(private, 审完后公开, 链接补在这).
下一篇(leftover $0 写回): 怎么把 "$10 的 Lite" 这个前置也省掉.

_文里略去了具体账号和卡信息. 仅供 Play Billing 计费机制研究, 请勿用于非自有账号._
