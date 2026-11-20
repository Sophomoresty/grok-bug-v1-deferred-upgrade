# 逆向 Grok Heavy 谷歌内购: 利用 Play 订阅替换参数实现 "一付三"

8 月底采样了三只市面流通的低价 Grok Heavy 账号 (两个 228 元非速刷号, 一个 88 元速刷号). 通过只读 gRPC 接口对齐账户指纹后, 顺着 Google Play 的内购链路完整逆向并复现了它的计费流程.

核心原理并不涉及改价: 先以 ~$11 购买一个月最低档的 `grok.lite`, 再通过 Play Billing 的订阅替换参数将订阅升级到 Heavy (`grok.ultra`), 首期扣款会被推迟到 Lite 周期结束日; 紧接着在 Play 订阅管理页取消续订, 当天实付维持在 Lite 的 ~$11, 即可拿到接近一个月的 Heavy 权益, 配合后续的写回机制可以延续到 3 个月乃至 1 年. 不过在 9 月初的实测中, xAI 服务端已开始拦截这类 $0 延期升级单的后续入账, 本文主要记录当时的机制分析, 参数排查与复现细节.

## 0x00 账号指纹与渠道来源

直接请求网页端 `/rest/subscriptions` 会触发 Cloudflare 403 拦截, 因此采样改用 App 侧的只读 gRPC 接口 (`GetUser`, `ListLinkedAccounts`, `GetGoogleObfuscatedId`, `GetSubscriptions`, `ListActiveSessions`). 三只样本账号的对比结果如下:

| 样本 | 渠道价 | 订阅记录 | 续订状态 | 关键时间线 |
|---|---|---|---|---|
| 卖家 A | 228 | 1 条 ultra, 0 条 lite | 已关续订 (`cancelAtPeriodEnd=true`) | 建行后 21 秒停续, Play 周期起点比 xAI 建行早约 50 秒 |
| 卖家 B | 228 | 3 条 ultra (其中 2 条同分钟失效), 0 条 lite | 自动续订, 未停续 | Play 周期锚点比有效行早 375 秒, 台北注册, 订购后 104 秒出现纽约会话 |
| 卖家 C | 88 | 1 条 ultra, 剩余 26.87 天 | 自动续订 | Play 周期起点在 08-25, 比该 xAI 账号创建时间 (08-26) 更早, xAI 建行晚 99 小时 |

从上述字段可以推出几个明确的边界:

三只账号全部为邮箱密码登录, 未绑定 Google OAuth 且未开启 MFA, 排除了通过 Google 登录态同步订阅的可能. 反编译 Grok 客户端代码后, 订阅相关的写接口仅有 `CreateBillingPortalSession`, `CreateStripeCustomer` 和 `SubscribeViaStripe`, 不存在 `ReportGoogle` 一类由客户端上报凭证的接口. 因此 Play 侧的订阅状态只能依赖 Google 后端的 RTDN 实时通知同步至 xAI.

查询 `GetProductsInfo` 官方目录可知, Stripe 侧 Heavy (`prod_Sdnv8D1IKHvyAs`) 定价为 $300/月或 $3000/年, Apple 侧仅有 `supergrok.pro.monthly.300`, Google 目录中的 `grok.ultra` 未标注低价档位. 88 元与 228 元的价格均不存在于 xAI 目录体系内, 计费差异必然来自 Google Play 侧的规则.

另外, 卖家 B 多出的 2 条同分钟失效记录属于直充失败后立即重试留下的残骸. 卖家 C 的 88 元账号售价约为 228 元的 39%, 但剩余天数为 26.87/31 (约 87%), 并非按剩余天数线性折算; 其 Play 账期起点 (08-25) 早于 xAI 账号注册时间 (08-26), 说明该渠道是先在 Google 账本上囤积 `grok.ultra` 账期, 再新建 xAI 账号绑定 GID.

## 0x01 实验环境与零消耗探测

测试环境由 macOS 上的 MuMu 模拟器 (通过本地 adb 端口连接) 与一台 Pixel 真机组成, Grok 客户端版本为 `1.2.18` (内置 BillingClient `9.1.0`), 运行时 Google Play Store 版本为 `52.9.21`, 调试框架使用 Frida 17. 需要注意静态反编译参考的 Play Store APK 为 `52.8.55`, 两个版本之间的混淆类名存在差异, 实际 hook 前需要重新导出类表.

绑在测试 Google 账号上的虚拟卡余额限制在 11 美元左右. 由于 `grok.ultra` 首期标价为 $99.99 (常规月付 $299.99), 限制卡内余额可以在脚本参数出错或误点确认时直接由发卡行拒绝扣款.

探测阶段严格执行零消耗原则: 通过 Frida hook `IInAppBillingService` 的 `transact` 方法, 调用 `d2` (`getBuyIntent`, api=17) 获取 `BUY_INTENT` 后, 要么不执行 `.send()`, 要么在弹窗拉起后仅导出页面布局与 OCR 文本并立即执行返回操作, 不触碰 Confirm 按钮. 单日测试数十组参数组合, 实际扣款保持为零.

## 0x02 客户端与 Play Billing 调用链

结合 Grok 与 Play Store 的反编译结果, 完整购买链路分为两部分.

在 Grok 客户端侧, 点击订阅入口会进入 `j9.z`, 首先向 xAI 服务端发起空请求 `GetGoogleObfuscatedId`, 获取服务端签发的 64 位十六进制字符串. 经对比验证, `userId`, 去连字符 `userId`, 大写变体及邮箱的本地哈希均不等于该返回值, 说明它完全由服务端按当前登录态签发. 随后 `h9.i.x` 将 offer, 64 位 ID 与当前持有的 Google 订阅传给 `launchBillingFlow`, 写入 `d2` 的 extras 参数中 (`accountId` 与 `oldSkuPurchaseToken`).

在 Google Play (`com.android.vending`) 侧, `szx.a` 构造 `GetBuyIntentParams`, `xyu.z` 将 SKU 编码为 `subs:ai.x.grok:grok.ultra` 形式的 docid, 再由 `xyu.D` 生成购买文档并签出 `BUY_INTENT`. 其中本地校验方法 `xux.H` 仅检查 SKU, type, offerToken 与 serializedDocid 列表长度是否一致, 不校验 `offerToken` 的实际归属.

弹窗拉起后展示的价格与可买性结果来自 `https://play-fe.googleapis.com/fdfe/ees/acquire?theme=2` 的 HTTP 响应 (请求体 protobuf 类为 `byvr`), 而实际计费单价绑定在更早的 `g2` (`skuDetails`) JSON 中, `byvr` 请求信封本身不含价格字段.

## 0x03 客户端改价的排除实验

基于上述调用链, 对客户端可能影响价格的参数逐一进行了验证, 均未实现有效降价.

首先测试跨 SKU 混用 token: 将 `grok.pro` 的促销 `offerToken` 搭配 `grok.ultra` SKU 传入 `d2`. `d2` 返回了 `RESPONSE_CODE=0` 并签出 `BUY_INTENT`, 但 `.send()` 拉起弹窗后提示 `"Subscription not available"`. 这说明 `d2` 返回 0 仅表示 PendingIntent 签发成功, 价格与可买性完全在 `Acquire` 服务端校验, 不能把 `d2` 返回码作为成功依据.

随后测试替换 `SKU_SERIALIZED_DOCID_LIST`, 传入 `grok.pro` 的商品文档. 弹窗显示为 `"SuperGrok Today 3-month $29.99"`, 形式上接近低价套餐, 但标题为 `SuperGrok` 而非 `SuperGrok Heavy`. `serializedDocid` 覆盖的是商品身份本身, 实际对应的是 `grok.pro` 的 3 月促销档.

其余请求参数同样无效: `SKU_OFFER_TYPE_LIST` 设为 `18` (`TRY_BEFORE_YOU_BUY`) 虽然已写入 `acquire` 请求参数, 弹窗仍显示 `$99.99`; 运行时修改 `swe.f` 为 `grok.pro` 的 `$29.99` token, 弹窗依旧为 `"Starting today $99.99/month"`; 通过 `additionalSkus` 拼接 `grok.pro` 时, 弹窗直接按两项求和显示 `"Today $129.98 = $99.99+$29.99"`.

本地 UI 与缓存层的修改也仅影响显示. 通过 hook `TextView.setText` 或 `JSONObject.put` 改写 `$99.99` 为 `$29.99` 时, 弹窗要么退出回桌面, 要么不读取该 JSON 字段. 直接修改 `/data/data/com.android.vending/app_commerce_acquire_cache` 下的 gzip 缓存文件中的价格字符串与 varint 数值后, 重启界面虽然能稳定渲染出 `$29.99/month` 连付 3 期, 但服务端 `skuDetails` 仍为 `$99.99`, 确认支付仍按原价结算.

## 0x04 ReplacementMode 参数与首扣推迟

在排除客户端改价后, 排查重点转向控制首次扣款时机的订阅替换参数 `subscriptionProductReplacementParamsList` (混淆类 `m1`, `t1`, `o1`, 枚举构造器 `l1.g(n)`). 使用一张已取消续订的 `grok.ultra` 作为 `oldSku`, 对 `g(2)` 至 `g(7)` 进行了对照测试:

| 构造调用 | 内部枚举值 | 支付弹窗原文 |
|---|---|---|
| `g(4)` | `3` (`WITHOUT_PRORATION`) | `"SuperGrok Heavy Starting Sep 29 $99.99/month"`, 无 Today 扣款行, 首扣推迟至 Sep 29 |
| `g(6)` | `5` (`CHARGE_FULL`) | `"Today $99.99 + 57 days (includes 27 days converted from the remaining time on your current plan)"` |
| `g(2)` / `g(3)` / `g(7)` | `1` / `2` / `6` | `"Something went wrong on our end. Please try again."` |

测试结果表明, `g(4)` (`WITHOUT_PRORATION`) 并没有改变目录价 `$99.99`, 而是将新订阅的首次扣款时间推迟到了被替换订阅的周期结束日. 构造该参数时需注意两处细节: `l1.g(n)` 的入参与内部 `zzg` 枚举值相差 1 (`g(4)` 对应 `zzg=3`); 且 protobuf 中 `field1` 为新 SKU, `field2` 为旧 SKU, 若两者顺序写反会直接触发 `DF-DFERH-01` 错误.

## 0x05 从 Lite 到 Heavy 的完整复现流程

利用上述机制, 完整路径为: 先购买一个月 `$9.99` 的 `grok.lite` 作为前置订阅, 再将其作为 `oldSku` 发起 `mode 3` (`WITHOUT_PRORATION`) 替换升级至 `grok.ultra`.

通过 Frida 调用 `d2` 发起升级的核心构造如下:

```js
ex.putString('oldSkuPurchaseToken', liteToken);      // 有效 Lite 订单的 purchaseToken
ex.putStringArrayList('skusToReplace', ['grok.lite']);
ex.putInt('replacementMode', 3);
ex.putString('accountId', liteReceiptObf);           // 必须与 Lite 收据上的 obfuscatedAccountId 一致
// 替换 proto: field1=新商品, field2=旧商品, l1.g(4) 对应 zzg=3
// 外层由 o1 包装序列化并写入 subscriptionProductReplacementParamsList
ex.putByteArray('subscriptionProductReplacementParamsList', bytes);
var bb = fd.d2(17, 'ai.x.grok', 'grok.ultra', 'subs', ex);
bb.getParcelable('BUY_INTENT').send();
```

除直接构造 `d2` 外, 也可以通过 hook 客户端的 `m1.s` 方法, 将代表 `CHARGE_FULL` 的参数 `6` 拦截替换为 `4` (`zzg=3`), 再从 Grok 设置页正常点击升级, 由官方流程自动携带当前 Lite token.

端到端实测过程中, 购买 `$9.99` Lite 时因模拟器, 数据中心 IP 与虚拟卡组合触发了约 2.5 小时的风控挂起 (Play 界面显示 `"Confirm plan before Sep 4"`). 待风控解除且 xAI 通过 RTDN 建出 Lite 记录后, 再发起 `grok.ultra` 升级. 弹窗显示为 `"Starting Oct 1, 2026 $299.99/month. Your first charge will occur on Oct 1"`, 不包含任何 `Starting today` 扣款行. 确认支付后当天扣款为 `$0`, 客户端立即切换为 Heavy 状态; 随后在 Play 订阅管理页取消续订 (`cancelAtPeriodEnd=true`), 即可阻止 Oct 1 的首扣发生. 本次总实付为 Lite 的 `$9.99 + 税 = $11.04` (约 79 RMB).

需要注意的是, 9 月初这次实测中, Play 侧的 `$0` 升级订单虽然已经生效, 但 xAI 侧的 RTDN 等待 16 小时以上仍未入账 (期间调用 `/rest/subscriptions/sync` 反而会先关闭旧的 Lite 记录, 造成权限空窗). 排查尝试了 `d2` 触发, `ack` 确认, 深链及 6 个猜想的 receipt 上报接口 (均返回 404), 均未能推动同步. 结合 8 月份样本可正常同步的时间线判断, xAI 服务端后续大概率增加了 "$0 延期单与 $299.99 目录价" 的一致性校验, 该路径在窗口期之后已无法在 xAI 侧完整落地.

## 0x06 调试过程中遇到的问题与处理

在自动化与脚本调试阶段, 主要遇到了以下五类技术问题:

1. **未确认订单阻塞计划变更**: 升级成交后如果未执行 `ack`, 后续再次发起订阅变更会被 `"Developer hasn't acknowledged your purchase"` 拦截. 需要在脚本中调用 `transact(902)` (按序写入接口标识, apiVersion `9`, 包名, `purchaseToken` 与参数 Bundle) 将 `acknowledged` 置为 `true`.
2. **`obfuscatedAccountId` 校验机制**: 直接传入 xAI `userId` 或邮箱本地哈希值作为 `accountId` 时, Play 弹窗可以正常出现, 但 xAI 侧查询订阅始终为空. 该值必须是在登录态下调用 `GetGoogleObfuscatedId` 获取的服务端签发值.
3. **Play 购买列表的账号绑定**: 在 Play 商店界面切换 Google 账号后, `e2` (`getPurchases`) 返回的仍是上一个账号的订阅库. IAB 购买列表绑定于底层账户而非 UI 视图, 切换账号必须执行 `REMOVE + ADD` 操作并通过 `library.db` 核对.
4. **混淆符号漂移与 Frida 崩溃**: 由于静态分析基于 Play `52.8.55`, 而设备运行版本为 `52.9.21`, 多个类名已发生变化 (例如 `cbbp` 变为 `cbhb`, `d2` 实现类变为 `xsi.H`), 每次适配均需先执行运行时 classdump. 此外 Frida 17 在 `com.android.vending` 进程中存在若干限制: 进程刚启动即 attach 会触发 Cronet `SIGSEGV`, 需先无 hook 打开一次支付弹窗再注入; `Java.array` 与 `Module.findExportByName` 不可用; hook 全量 Activity 回调会导致 Cronet 进入解释器崩溃. 进程崩溃后若残留 `:recovery_mode` 进程, 后续 `BUY_INTENT` 会全部跳转至 `"Google Play Store is updating"`, 需先 kill 恢复进程并将 `files/recovery_state_` 覆写为 30 字节的 `NONE`.
5. **`FLAG_SECURE` 限制**: 支付确认页开启了防截屏保护, `uiautomator dump` 常返回 0 字节, 界面文案校验需统一改用 `screencap` 截图配合 OCR 识别.

## 0x07 成本对照与代码仓库

| 路线 | 成本 | 实际结果 |
|---|---|---|
| 市面 228 非速刷号 | 228 RMB | 成品账号, 工艺来源不可控 |
| 复现 "一付三" | $11.04 | Play 侧生成 $0 Heavy 订单并在周期末停续 |
| 市面 88 速刷号 | 88 RMB | 购买时剩余 26.87 天, 三天后 Play 侧撤单, 1 分钟内连续 3 次重试全部失效 |

脱敏后的 hook 与驱动脚本位于 GitHub 仓库: [https://github.com/Sophomoresty/grok-play-deferred-upgrade](https://github.com/Sophomoresty/grok-play-deferred-upgrade)

## 适用范围

该 bug 最早来自于 7 月份的 cc max20x 的谷歌低价号, 后横向迁移至 grok 等一系列谷歌 app.

### 🚩 友情链接

[![GenericAgent](https://img.shields.io/badge/Agent_Framework-GenericAgent-orange?style=for-the-badge&logo=github)](https://github.com/lsdefine/GenericAgent)
[![LinuxDo](https://img.shields.io/badge/社区-LinuxDo-blue?style=for-the-badge)](https://linux.do/)

_本文略去了具体账号与支付卡信息, 仅用于 Google Play Billing 计费机制研究, 请勿用于非自有账号._
