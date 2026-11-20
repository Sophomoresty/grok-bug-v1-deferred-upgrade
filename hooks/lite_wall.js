// Sanitized research copy. Ops/account/card/egress specifics removed.
// grok.lite acquire hook: g2 offers -> d2(order, accountId=GID). yearlite = lite -> P1Y deferred replace.
'use strict';
import Java from 'frida-java-bridge';

var PKG = 'ai.x.grok';
var SKU = 'grok.lite';
// Placeholder: replace with a live offerIdToken (from g2 subscriptionOfferDetails)
// or rely on the regular-p1m / lite-p3m branches that read it live below.
var LITE_P3M_TOKEN = 'PLACEHOLDER.LITE.P3M.OFFER.TOKEN';
var WANT_P3M = true;
var SKIP_ACCOUNT_ID = false;
// Placeholder 64-hex. billing_core.prepare_hooks() patches this to the live GID
// before frida-compile; the regex expects exactly [0-9a-f]{64}.
var GID = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function openBilling(service) {
  try {
    var fd = Java.cast(
      Java.use('com.google.android.gms.internal.play_billing.e').T1(service),
      Java.use('com.google.android.gms.internal.play_billing.d')
    );
    return {
      gen: '1218',
      ver: '9.1.1',
      g2: function (api, pkg, type, skuB, extra) {
        return fd.g2(api, pkg, type, skuB, extra);
      },
      d2: function (api, pkg, sku, type, ex) {
        return fd.d2(api, pkg, sku, type, ex);
      },
      e2: function (pkg, type, token) {
        return fd.e2(pkg, type, token);
      },
    };
  } catch (eOld) {
    var l4 = Java.use('c00.l4').$new(service);
    return {
      gen: '1246',
      ver: '9.1.0-billing-eap02',
      g2: function (api, pkg, type, skuB, extra) {
        var use = api === 21 ? 20 : api;
        var r = l4.Q1(use, pkg, type, skuB, extra);
        var details = null;
        try {
          details = r.getStringArrayList('DETAILS_LIST');
        } catch (e1) {}
        if (!details || details.isEmpty()) r = l4.Q1(17, pkg, type, skuB, extra);
        return r;
      },
      d2: function (api, pkg, sku, type, ex) {
        var bb = l4.R1(api, pkg, sku, type, ex);
        var rc = -1;
        try {
          rc = bb.getInt('RESPONSE_CODE');
        } catch (e2) {}
        if (rc !== 0) bb = l4.R1(28, pkg, sku, type, ex);
        return bb;
      },
      e2: function (pkg, type, token) {
        return l4.W1(pkg, type, token);
      },
    };
  }
}

function parseOffers(jo) {
  var offers = [];
  if (!jo.has('subscriptionOfferDetails')) return offers;
  var arr = jo.getJSONArray('subscriptionOfferDetails');
  for (var i = 0; i < arr.length(); i++) {
    var o = arr.getJSONObject(i);
    var oid = o.has('offerId') && !o.isNull('offerId') ? String(o.getString('offerId')) : '';
    var rec = {
      offerId: oid,
      offerIdToken: o.getString('offerIdToken'),
      nPhases: 0,
      billing: '',
      price: '',
      micros: '',
    };
    try {
      var phases = o.getJSONArray('pricingPhases');
      rec.nPhases = phases.length();
      var ph0 = phases.getJSONObject(0);
      rec.price = ph0.has('formattedPrice') ? String(ph0.getString('formattedPrice')) : '';
      rec.micros = ph0.has('priceAmountMicros') ? String(ph0.getLong('priceAmountMicros')) : '';
      rec.billing = ph0.has('billingPeriod') ? String(ph0.getString('billingPeriod')) : '';
    } catch (eP) {}
    offers.push(rec);
  }
  return offers;
}

function pickYearly(offers) {
  var yearly = [];
  var i;
  var id;
  for (i = 0; i < (offers || []).length; i++) {
    if (String(offers[i].billing) === 'P1Y') yearly.push(offers[i]);
  }
  // Intro / 1付3 / promo charge today. Leftover uses the empty-oid base P1Y.
  for (i = 0; i < yearly.length; i++) {
    id = String(yearly[i].offerId || '');
    if (id === '' && Number(yearly[i].nPhases || 1) <= 1) {
      yearly[i].offerId = 'regular-p1y';
      return yearly[i];
    }
  }
  for (i = 0; i < yearly.length; i++) {
    id = String(yearly[i].offerId || '');
    if (id.indexOf('p3m') < 0 && id.indexOf('may2026') < 0 && id.indexOf('intro') < 0) {
      if (!id) yearly[i].offerId = 'regular-p1y';
      return yearly[i];
    }
  }
  return null;
}

function bindAndRun(handler) {
  return new Promise(function (resolve) {
    Java.perform(function () {
      try {
        var Intent = Java.use('android.content.Intent');
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var Conn = Java.registerClass({
          name: 'com.local.LiteYear' + Date.now(),
          implements: [Java.use('android.content.ServiceConnection')],
          methods: {
            onServiceConnected: function (name, service) {
              var out = { ok: false };
              try {
                var fd = openBilling(service);
                out.billingGen = fd.gen;
                handler(fd, out, service);
              } catch (e) {
                out.err = String(e);
              }
              resolve(out);
            },
            onServiceDisconnected: function () {},
            onNullBinding: function () {
              resolve({ ok: false, err: 'null_binding' });
            },
            onBindingDied: function () {},
          },
        });
        var intent = Intent.$new('com.android.vending.billing.InAppBillingService.BIND');
        intent.setPackage('com.android.vending');
        var ok = ctx.bindService(intent, Conn.$new(), 1);
        if (!ok) resolve({ ok: false, err: 'bind_false' });
      } catch (e) {
        resolve({ ok: false, outer: String(e) });
      }
    });
  });
}

function inspectFd(fd, out) {
  var Bundle = Java.use('android.os.Bundle');
  var AL = Java.use('java.util.ArrayList');
  var JSONObject = Java.use('org.json.JSONObject');
  out.purchases = [];
  try {
    var pb = fd.e2(PKG, 'subs', null);
    out.e2rc = pb.getInt('RESPONSE_CODE');
    var dlist = pb.getStringArrayList('INAPP_PURCHASE_DATA_LIST');
    if (dlist) {
      var it = dlist.iterator();
      while (it.hasNext()) {
        var js = String(it.next());
        var rec = { rawHead: js.slice(0, 280) };
        try {
          var joP = JSONObject.$new(js);
          rec.productId = joP.has('productId') ? String(joP.getString('productId')) : '';
          rec.tokenHead = joP.has('purchaseToken') ? String(joP.getString('purchaseToken')).slice(0, 24) : '';
          rec.orderId = joP.has('orderId') ? String(joP.getString('orderId')) : '';
          rec.autoRenewing = joP.has('autoRenewing') ? joP.getBoolean('autoRenewing') : null;
          rec.obfHead = joP.has('obfuscatedAccountId')
            ? String(joP.getString('obfuscatedAccountId')).slice(0, 16)
            : '';
          rec.purchaseToken = joP.has('purchaseToken') ? String(joP.getString('purchaseToken')) : '';
          rec.obfuscatedAccountId = joP.has('obfuscatedAccountId')
            ? String(joP.getString('obfuscatedAccountId'))
            : '';
        } catch (eJ) {
          rec.parseErr = String(eJ);
        }
        out.purchases.push(rec);
      }
    }
  } catch (e2) {
    out.e2err = String(e2);
  }

  var skuB = Bundle.$new();
  var ids = AL.$new();
  ids.add(SKU);
  skuB.putStringArrayList('ITEM_ID_LIST', ids);
  var extra = Bundle.$new();
  extra.putString('playBillingLibraryVersion', '9.1.1');
  extra.putString('SKU_DETAILS_RESPONSE_FORMAT', 'PRODUCT_DETAILS');
  extra.putBoolean('enablePendingPurchases', true);
  var multi = AL.$new();
  multi.add('subs');
  extra.putStringArrayList('PRODUCT_TYPES_TO_RETURN_MULTIPLE_OFFERS', multi);
  extra.putBoolean('SHOULD_RETURN_UNFETCHED_PRODUCTS', true);
  var r = fd.g2(21, PKG, 'subs', skuB, extra);
  out.g2rc = r.getInt('RESPONSE_CODE');
  var details = r.getStringArrayList('DETAILS_LIST');
  out.offers = [];
  out.skuTok = null;
  if (details && !details.isEmpty()) {
    var row = String(details.get(0));
    out.rowHead = row.slice(0, 280);
    var jo = JSONObject.$new(row);
    out.skuTok = jo.getString('skuDetailsToken');
    out.offers = parseOffers(jo);
  }
  return { Bundle: Bundle, AL: AL, JSONObject: JSONObject };
}

function putReplaceProto(extras, AL, oldSku, newSku, modeArg) {
  var t1 = Java.use('com.google.android.gms.internal.play_billing.t1');
  var m1c = Java.use('com.google.android.gms.internal.play_billing.m1');
  var o1c = Java.use('com.google.android.gms.internal.play_billing.o1');
  var newB = t1.p();
  newB.e('subs:ai.x.grok:' + newSku);
  var oldB = t1.p();
  oldB.e('subs:ai.x.grok:' + oldSku);
  var lb = m1c.p();
  lb.e(newB);
  lb.f(oldB);
  lb.g(modeArg);
  var ral = Java.use('java.util.ArrayList').$new();
  ral.add(lb.a());
  var ob = o1c.p();
  ob.e(ral);
  var bytes = ob.a().b();
  extras.putByteArray('subscriptionProductReplacementParamsList', bytes);
  return bytes.length;
}

function ack902(service, token, out) {
  try {
    var Binder = Java.use('android.os.IBinder');
    var raw = Java.cast(service, Binder);
    var Parcel = Java.use('android.os.Parcel');
    var Bundle = Java.use('android.os.Bundle');
    var extra = Bundle.$new();
    extra.putString('playBillingLibraryVersion', '9.1.1');
    extra.putBoolean('enablePendingPurchases', true);
    var data = Parcel.obtain();
    var reply = Parcel.obtain();
    data.writeInterfaceToken('com.android.vending.billing.IInAppBillingService');
    data.writeInt(9);
    data.writeString(PKG);
    data.writeString(token);
    data.writeInt(1);
    extra.writeToParcel(data, 0);
    out.ackTransact = raw.transact(902, data, reply, 0);
    try {
      reply.readException();
      out.ackEx = 'none';
    } catch (e0) {
      out.ackEx = String(e0).slice(0, 120);
    }
    data.recycle();
    reply.recycle();
  } catch (eAck) {
    out.ackErr = String(eAck).slice(0, 160);
  }
}

function sendYearBuy(fd, Bundle, AL, out, skuTok, offer, replace) {
  var ex = Bundle.$new();
  ex.putBoolean('enablePendingPurchases', true);
  ex.putString('playBillingLibraryVersion', '9.1.1');
  var ot = AL.$new();
  ot.add(offer.offerIdToken);
  var st = AL.$new();
  st.add(skuTok);
  ex.putStringArrayList('SKU_OFFER_ID_TOKEN_LIST', ot);
  ex.putStringArrayList('skuDetailsTokens', st);
  if (SKIP_ACCOUNT_ID) {
    out.accountId = '';
    out.skipAccountId = true;
  } else {
    ex.putString('accountId', GID);
    out.accountId = GID.slice(0, 16);
  }
  out.offerId = offer.offerId || 'regular-p1y';
  out.offerPrice = offer.price || '';
  out.offerBilling = offer.billing || '';
  if (replace && replace.token) {
    ex.putString('oldSkuPurchaseToken', replace.token);
    var olds = AL.$new();
    olds.add(replace.oldSku || SKU);
    ex.putStringArrayList('skusToReplace', olds);
    var modeArg = 4;
    ex.putInt('replacementMode', 3);
    ex.putInt('replaceSkusProrationMode', 3);
    out.protoN = putReplaceProto(ex, AL, replace.oldSku || SKU, SKU, modeArg);
    out.replaceTokenHead = String(replace.token).slice(0, 24);
    out.modeArg = modeArg;
  }
  var bb = fd.d2(17, PKG, SKU, 'subs', ex);
  out.d2rc = bb.getInt('RESPONSE_CODE');
  try {
    out.d2msg = String(bb.getString('DEBUG_MESSAGE') || '');
  } catch (e0) {
    out.d2msg = '';
  }
  out.d2keys = String(bb.keySet());
  var pi = bb.getParcelable('BUY_INTENT');
  out.hasPI = !!pi;
  if (pi) {
    Java.cast(pi, Java.use('android.app.PendingIntent')).send();
    out.sent = true;
  }
  out.ok = out.d2rc === 0 && !!pi;
}

rpc.exports = {
  inspect: function () {
    return bindAndRun(function (fd, out) {
      inspectFd(fd, out);
      out.ok = true;
    });
  },
  yearlite: function () {
    SKIP_ACCOUNT_ID = false;
    return bindAndRun(function (fd, out, service) {
      var cls = inspectFd(fd, out);
      var offer = pickYearly(out.offers || []);
      if (!out.skuTok) {
        out.err = 'no_lite_sku_token';
        return;
      }
      if (!offer) {
        out.err = 'no_lite_p1y_offer';
        return;
      }
      var lite = null;
      var i;
      for (i = 0; i < (out.purchases || []).length; i++) {
        var p = out.purchases[i];
        if (p.productId === 'grok.lite' && p.purchaseToken && p.autoRenewing) {
          lite = {
            token: p.purchaseToken,
            accountId: p.obfuscatedAccountId || GID,
            oldSku: 'grok.lite',
          };
          break;
        }
      }
      if (!lite) {
        out.err = 'no_monthly_lite_for_yearlite';
        return;
      }
      if (service && lite.token) ack902(service, lite.token, out);
      sendYearBuy(fd, cls.Bundle, cls.AL, out, out.skuTok, offer, lite);
    });
  },
  p1m: function () {
    WANT_P3M = false;
    SKIP_ACCOUNT_ID = false;
    return rpc.exports.fire();
  },
  p1mnogid: function () {
    WANT_P3M = false;
    SKIP_ACCOUNT_ID = true;
    return rpc.exports.fire();
  },
  destp1m: function (gid) {
    WANT_P3M = false;
    SKIP_ACCOUNT_ID = false;
    if (typeof gid === 'string' && gid.length >= 32) GID = gid;
    return rpc.exports.fire();
  },
  fire: function () {
    return new Promise(function (resolve) {
      Java.perform(function () {
        try {
          var Intent = Java.use('android.content.Intent');
          var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          var Conn = Java.registerClass({
            name: 'com.local.LiteWall' + Date.now(),
            implements: [Java.use('android.content.ServiceConnection')],
            methods: {
              onServiceConnected: function (name, service) {
                var out = { ok: false };
                try {
                  var fd = openBilling(service);
                  out.billingGen = fd.gen;
                  var Bundle = Java.use('android.os.Bundle');
                  var AL = Java.use('java.util.ArrayList');
                  var JSONObject = Java.use('org.json.JSONObject');
                  var skuB = Bundle.$new();
                  var ids = AL.$new();
                  ids.add(SKU);
                  skuB.putStringArrayList('ITEM_ID_LIST', ids);
                  var extra = Bundle.$new();
                  extra.putString('playBillingLibraryVersion', fd.ver);
                  extra.putString('SKU_DETAILS_RESPONSE_FORMAT', 'PRODUCT_DETAILS');
                  extra.putBoolean('enablePendingPurchases', true);
                  var multi = AL.$new();
                  multi.add('subs');
                  extra.putStringArrayList('PRODUCT_TYPES_TO_RETURN_MULTIPLE_OFFERS', multi);
                  extra.putBoolean('SHOULD_RETURN_UNFETCHED_PRODUCTS', true);
                  var r = fd.g2(21, PKG, 'subs', skuB, extra);
                  out.g2rc = r.getInt('RESPONSE_CODE');
                  var details = r.getStringArrayList('DETAILS_LIST');
                  var skuTok = null;
                  var offerTok = LITE_P3M_TOKEN;
                  var row = null;
                  if (details && !details.isEmpty()) {
                    row = String(details.get(0));
                    var jo = JSONObject.$new(row);
                    skuTok = jo.getString('skuDetailsToken');
                    if (jo.has('subscriptionOfferDetails')) {
                      var arr = jo.getJSONArray('subscriptionOfferDetails');
                      for (var i = 0; i < arr.length(); i++) {
                        var o = arr.getJSONObject(i);
                        var oid = o.has('offerId') && !o.isNull('offerId') ? String(o.getString('offerId')) : '';
                        if (WANT_P3M && oid.indexOf('lite-p3m') >= 0) {
                          offerTok = o.getString('offerIdToken');
                          out.offerId = oid;
                          break;
                        }
                        if (!WANT_P3M && oid === '') {
                          offerTok = o.getString('offerIdToken');
                          out.offerId = 'regular-p1m';
                          break;
                        }
                      }
                    }
                  }
                  out.rowHead = row ? row.slice(0, 220) : null;
                  out.offerTokHead = String(offerTok).slice(0, 24);
                  if (!skuTok) {
                    out.err = 'no_lite_sku_token';
                    resolve(out);
                    return;
                  }
                  var ex = Bundle.$new();
                  ex.putBoolean('enablePendingPurchases', true);
                  ex.putString('playBillingLibraryVersion', fd.ver);
                  var ot = AL.$new();
                  ot.add(offerTok);
                  var st = AL.$new();
                  st.add(skuTok);
                  ex.putStringArrayList('SKU_OFFER_ID_TOKEN_LIST', ot);
                  ex.putStringArrayList('skuDetailsTokens', st);
                  if (SKIP_ACCOUNT_ID) {
                    out.accountId = '';
                    out.skippedAccountId = true;
                  } else {
                    ex.putString('accountId', GID);
                    out.accountId = GID.slice(0, 16);
                  }
                  var bb = fd.d2(17, PKG, SKU, 'subs', ex);
                  out.d2rc = bb.getInt('RESPONSE_CODE');
                  try {
                    out.d2msg = String(bb.getString('DEBUG_MESSAGE') || '');
                  } catch (e0) {
                    out.d2msg = '';
                  }
                  out.d2keys = String(bb.keySet());
                  var pi = bb.getParcelable('BUY_INTENT');
                  out.hasPI = !!pi;
                  if (pi) {
                    Java.cast(pi, Java.use('android.app.PendingIntent')).send();
                    out.sent = true;
                  }
                  out.ok = out.d2rc === 0 && !!pi;
                } catch (e) {
                  out.err = String(e);
                }
                resolve(out);
              },
              onServiceDisconnected: function () {},
              onNullBinding: function () {
                resolve({ ok: false, err: 'null_binding' });
              },
              onBindingDied: function () {},
            },
          });
          var intent = Intent.$new('com.android.vending.billing.InAppBillingService.BIND');
          intent.setPackage('com.android.vending');
          var ok = ctx.bindService(intent, Conn.$new(), 1);
          if (!ok) resolve({ ok: false, err: 'bind_false' });
        } catch (e) {
          resolve({ ok: false, outer: String(e) });
        }
      });
    });
  },
};
