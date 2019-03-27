
/******** MD5加密开始 ********/
/* http://blog.csdn.net/xw505501936/article/details/48224593 */
(function ($) {
    'use strict';

    /*
    * Add integers, wrapping at 2^32. This uses 16-bit operations internally
    * to work around bugs in some JS interpreters.
    */
    function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF),
            msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
    * Bitwise rotate a 32-bit number to the left.
    */
    function bit_rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
    * These functions implement the four basic operations the algorithm uses.
    */
    function md5_cmn(q, a, b, x, s, t) {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }

    function md5_ff(a, b, c, d, x, s, t) {
        return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function md5_gg(a, b, c, d, x, s, t) {
        return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function md5_hh(a, b, c, d, x, s, t) {
        return md5_cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function md5_ii(a, b, c, d, x, s, t) {
        return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
    * Calculate the MD5 of an array of little-endian words, and a bit length.
    */
    function binl_md5(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << (len % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        var i, olda, oldb, oldc, oldd,
            a = 1732584193,
            b = -271733879,
            c = -1732584194,
            d = 271733878;

        for (i = 0; i < x.length; i += 16) {
            olda = a;
            oldb = b;
            oldc = c;
            oldd = d;

            a = md5_ff(a, b, c, d, x[i], 7, -680876936);
            d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
            b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
            d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
            b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
            d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
            b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
            d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

            a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
            d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
            b = md5_gg(b, c, d, a, x[i], 20, -373897302);
            a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
            d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
            d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
            b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
            d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
            b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
            d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
            b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
            d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
            b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
            d = md5_hh(d, a, b, c, x[i], 11, -358537222);
            c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
            b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
            d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
            b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

            a = md5_ii(a, b, c, d, x[i], 6, -198630844);
            d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
            d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
            c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
            d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
            b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
            d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
            b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }
        return [a, b, c, d];
    }

    /*
    * Convert an array of little-endian words to a string
    */
    function binl2rstr(input) {
        var i,
            output = '';
        for (i = 0; i < input.length * 32; i += 8) {
            output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
        }
        return output;
    }

    /*
    * Convert a raw string to an array of little-endian words
    * Characters >255 have their high-byte silently ignored.
    */
    function rstr2binl(input) {
        var i,
            output = [];
        output[(input.length >> 2) - 1] = undefined;
        for (i = 0; i < output.length; i += 1) {
            output[i] = 0;
        }
        for (i = 0; i < input.length * 8; i += 8) {
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
        }
        return output;
    }

    /*
    * Calculate the MD5 of a raw string
    */
    function rstr_md5(s) {
        return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
    }

    /*
    * Calculate the HMAC-MD5, of a key and some data (raw strings)
    */
    function rstr_hmac_md5(key, data) {
        var i,
            bkey = rstr2binl(key),
            ipad = [],
            opad = [],
            hash;
        ipad[15] = opad[15] = undefined;
        if (bkey.length > 16) {
            bkey = binl_md5(bkey, key.length * 8);
        }
        for (i = 0; i < 16; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }
        hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
        return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
    }

    /*
    * Convert a raw string to a hex string
    */
    function rstr2hex(input) {
        var hex_tab = '0123456789abcdef',
            output = '',
            x,
            i;
        for (i = 0; i < input.length; i += 1) {
            x = input.charCodeAt(i);
            output += hex_tab.charAt((x >>> 4) & 0x0F) +
                hex_tab.charAt(x & 0x0F);
        }
        return output;
    }

    /*
    * Encode a string as utf-8
    */
    function str2rstr_utf8(input) {
        return unescape(encodeURIComponent(input));
    }

    /*
    * Take string arguments and return either raw or hex encoded strings
    */
    function raw_md5(s) {
        return rstr_md5(str2rstr_utf8(s));
    }

    function hex_md5(s) {
        return rstr2hex(raw_md5(s));
    }

    function raw_hmac_md5(k, d) {
        return rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d));
    }

    function hex_hmac_md5(k, d) {
        return rstr2hex(raw_hmac_md5(k, d));
    }

    function md5(string, key, raw) {
        if (!key) {
            if (!raw) {
                return hex_md5(string);
            }
            return raw_md5(string);
        }
        if (!raw) {
            return hex_hmac_md5(key, string);
        }
        return raw_hmac_md5(key, string);
    }

    if (typeof define === 'function' && define.amd) {
        define(function () {
            return md5;
        });
    } else {
        $.md5 = md5;
    }
}(this));

var layer = layui.layer;

/**
 * 系统提示信息
 * @param msg
 */
function dmstoast(msg, level, callback) {
    //带回调函数的处理
    if (callback && typeof(callback) === "function") {
        layer.msg(msg, {time: 3000}, function () {
            callback();
        });
    }
    else {
        layer.msg(msg, {time: 3000});
    }

}

/**
 * 系统提示信息。没有定时自动关闭
 * @param msg
 */
function dmstoastLong(msg) {
    layer.msg(msg,
        {
            shadeClose: true, //开启遮罩关闭
            shade: [0.5, '#000'],// 遮罩层背景色
            time: 30000
        }
    );
}

/**
 * TMS系统弹出消息提示框
 * @param msg 消息体文字
 * @param level  消息级别
 * @param callback 回调函数
 */
function dmsalert(msg, level, callback) {
    //带回调函数的处理
    if (callback && typeof(callback) === "function") {
        //Warning
        if (level == "W") {
            var index = layer.alert(msg,
                {skin: 'layui-layer-lan', title: "系统提示信息", icon: 0, closeBtn: 0},
                function () {
                    layer.close(index);
                    callback();
                }
            );
        }
        //Error
        else if (level == "E") {
            var index = layer.alert(msg,
                {skin: 'layui-layer-lan', title: "系统提示信息", icon: 2, closeBtn: 0},
                function () {
                    layer.close(index);
                    callback();
                }
            );
        }
        //Success
        else if (level == "S") {
            var index = layer.alert(msg,
                {skin: 'layui-layer-lan', title: "系统提示信息", icon: 1, closeBtn: 0},
                function () {
                    layer.close(index);
                    callback();
                }
            );
        }
        //Ask
        else if (level == "A") {
            var index = layer.alert(msg,
                {skin: 'layui-layer-lan', title: "系统提示信息", icon: 3, closeBtn: 0},
                function () {
                    layer.close(index);
                    callback();
                }
            );
        }
        else {
            var index = layer.alert(msg,
                {skin: 'layui-layer-lan', title: "系统提示信息", icon: 5, closeBtn: 0},
                function () {
                    layer.close(index);
                    callback();
                }
            );
        }

    }
    //不具有回调函数的处理
    else {

        //Warning
        if (level == "W") {
            layer.alert(msg, {skin: 'layui-layer-lan', title: "系统提示信息", icon: 0, closeBtn: 0});
        }
        //Error
        else if (level == "E") {
            layer.alert(msg, {skin: 'layui-layer-lan', title: "系统提示信息", icon: 2, closeBtn: 0});
        }
        //Success
        else if (level == "S") {
            layer.alert(msg, {skin: 'layui-layer-lan', title: "系统提示信息", icon: 1, closeBtn: 0});
        }
        //Ask
        else if (level == "A") {
            layer.alert(msg, {skin: 'layui-layer-lan', title: "系统提示信息", icon: 3, closeBtn: 0});
        }
        else {
            layer.alert(msg, {skin: 'layui-layer-lan', title: "系统提示信息", icon: 5, closeBtn: 0});
        }
    }

}


/**
 * 判断字符串是否为空或者null
 * @param strVal  字符串文本
 * @returns {Boolean}
 */
function isNullOrEmpty(strVal) {
    if (strVal == '' || strVal == null || strVal == undefined) {
        return true;
    } else {
        return false;
    }
}

/**
 * 判断是否是数字
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isNumber(str) {
    res = /^(\+|\-)?\d+$/;
    var re = new RegExp(res);
    return !(str.match(re) == null);
}

/**
 * 判断是否是手机号码
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isMobile(str) {
    res = /^1[3|4|5|8]\d{9}$/;
    var re = new RegExp(res);
    return !(str.match(re) == null);
}

/**
 * 判断是否是固定座机
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isTelephone(str) {
    res = /(^[0-9]{3,4}\-[0-9]{8}$)/;
    var re = new RegExp(res);
    return !(str.match(re) == null);
}

/**
 * 判断是否是传真号
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isFax(str) {
    res = /(^[0-9]{3,4}\-[0-9]{7,8}$)/;
    var re = new RegExp(res);
    return !(str.match(re) == null);
}

/**
 * 判断是否是网址
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isWebSite(str) {
    var reg = /^(([A-Za-z-~]+)\.)+(([A-Za-z0-9-~]+)\.)+([A-Za-z0-9-~\/])+$/;
    var re = new RegExp(reg);
    return !(str.match(re) == null);
}

/**
 * 判断是否是400服务电话
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function is400Telephone(str) {
    var s = str.replace(/-/g, "");

    if (s.length == 10) {
        res = /(^[4][0][0][0-9]{0,2}\-[0-9]{2,5}\-[0-9]{2,5}$)/;
        var re = new RegExp(res);
        return !(str.match(re) == null);

    } else {
        return false;
    }
}

/**
 * 判断是否是正整数
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isInteger(str) {
    res = /^(\+|\-)?\d+$/;
    var re = new RegExp(res);
    if (str.match(re) == null) {
        return false;
    }
    var intval = parseInt(str, 10);
    if (intval == 0 || intval) {
        return true;
    } else {
        return false;
    }
}

/**
 * 判断是否是正确的  数字，带小数
 * @param str 字符串文本
 * @returns true为数字 false为其他
 */
function isFloat(s) {
    var patrn = /^(0|[1-9]\d*|(0|[1-9]\d*)\.\d*[0|1-9]|(0|[1-9]\d*)\.)$/;
    if (!patrn.exec(s)) return false
    return true
}


////判断 必须由英文字母开始的   由 数字和字母组成的
function checkStringParth_1(str) {
    var patn = /^[a-zA-Z]+[a-zA-Z0-9]+$/;
    if (!patn.test(str)) {
        return false;
    }
    else {
        return true;
    }
}

////判断 必须由数字和字母 中下划线或 下划线 组成的
function checkStringParth_2(str) {
    var patn = /^[0-9a-zA-Z_\-]*$/;
    if (!patn.test(str)) {
        return false;
    }
    else {
        return true;
    }
}

/*
 * 日期转化为 yyyy-MM-dd HH:MM:SS
 */
function getNowFormatDate(date) {
    var seperator1 = "-";
    var seperator2 = ":";
    var month = date.getMonth() + 1;
    var strDate = date.getDate();
    if(month >= 1 && month <= 9) {
        month = "0" + month;
    }
    if(strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    var currentdate = date.getFullYear() + seperator1 + month + seperator1 + strDate +
        " " + date.getHours() + seperator2 + date.getMinutes() +
        seperator2 + date.getSeconds();
    return currentdate;
}

/**
 * 获取yyyyMMdd格式的日期字符串
 * @param {Object} date 需要格式化的日期对象
 */
function getDateFormatYYYYMMDD(date){
    var strMonth = date.getMonth() + 1;
    var strDate = date.getDate();
    if (strMonth >= 1 && strMonth <= 9) {
        strMonth = "0" + strMonth;
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    return '' + date.getFullYear() + strMonth + strDate;
}

/**
 * 获取yyyy-MM-dd格式的日期字符串
 * @param {Object} date 需要格式化的日期对象
 */
function getDateFormatYYYY_MM_DD(date){
    var strMonth = date.getMonth() + 1;
    var strDate = date.getDate();
    if (strMonth >= 1 && strMonth <= 9) {
        strMonth = "0" + strMonth;
    }
    if (strDate >= 0 && strDate <= 9) {
        strDate = "0" + strDate;
    }
    return date.getFullYear() +"-"+ strMonth +"-"+ strDate;
}

/**
 * 判断字符串是否包含字符
 * @param PsString  原文本字符串
 * @param SeachString 待检索的字符串
 * @returns {Boolean}
 */
function containsSeachStr(PsString, SeachString) {
    if (PsString.length > 0 && SeachString.length > 0) {
        if (PsString.indexOf(SeachString) != -1) {
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
}

/**
 * 获取本地缓存的用户信息
 */
function getUserInfo() {
    var userJsonStr = window.localStorage.getItem("VW.AUTO_USER_JSON");
    //console.log("-->"+userJsonStr);
    var userObj = undefined;
    if (userJsonStr != undefined && userJsonStr != '' && userJsonStr != 'undefined'&&userJsonStr!=null&&userJsonStr!="null") {
        userObj = JSON.parse(userJsonStr);
    } else {
        userObj = {
            "vaccount": "",
            "vrealName": ""
        };
    }
    return userObj;
}


/**
 * 获取验签字符串
 */
function getSignature() {
    var tmpSignStr = '';
    var userInfo = getUserInfo();
    tmpSignStr = userInfo.vaccount + dms_boot_config.companyCode + dms_boot_config.secretKey;
    tmpSignStr = md5(tmpSignStr);
    return tmpSignStr;
}

/**
 * 获取Ajax请求的真正url
 */
function getAjaxRequestUrl(ajax_url,page,limit) {
    var userInfo = getUserInfo();
    var realUrl = dms_boot_config.hostUrl+ajax_url;
    realUrl += '?usercode=' + userInfo.vaccount;
    realUrl += '&companycode=' + dms_boot_config.companyCode;
    realUrl += '&signature=' + getSignature();
    realUrl += '&version=' + dms_boot_config.localVerson;
    realUrl += '&r=' + Math.random();
    realUrl += '&model='+dms_boot_config.model;
    if(page>0 && limit>0)
    {
        realUrl += '&page=' + page;
        realUrl += '&limit=' + limit;
    }
    return realUrl;
}

/**
 * 调用服务端公用函数
 * @param urlStr   URL地址
 * @param dataObj  调用服务端时的参数
 * @param callback 调用成功后的回调函数
 * @param show_layer 是否显示遮罩层
 */
function callAjax(ajax_url, jsonDataObj,callback, page,limit,show_layer) {

    //弹出遮罩层
    var layer_index = 0;
    if (show_layer != 0) {
        layer_index = layer.load(1, {shade: [0.5, '#000']});
    }
    try {

        //系统处理掉创建人信息
        var userInfo = getUserInfo();
        jsonDataObj.nCreator = userInfo.id;
        jsonDataObj.vCreatorName = userInfo.vrealName;

        $.ajax({
            type: "POST",
            url: getAjaxRequestUrl(ajax_url,page,limit),
            data: {'inParaJsonStr': JSON.stringify(jsonDataObj)},
            cache: false,
            dataType: 'JSON',
            success: function (data) {
                //关闭遮罩层
                if (show_layer != 0) {
                    layer.close(layer_index);
                }
                if (typeof(data) == 'object') {
                    //返回Json对象
                    callback(data, dms_boot_config.CALL_URL_OK);
                } else {
                    dmstoast('服务器返回数据类型不支持，请联系管理员！');
                }
            },
            error: function (XMLHttpRequest, textStatus, errorThrown) {
                //关闭遮罩层
                if (show_layer != 0) {
                    layer.close(layer_index);
                }
                var data = {'code': 'E', 'msg': '服务器,网络等情况异常[' + textStatus + ']，请稍后再试！'};
                callback(data, dms_boot_config.CALL_URL_ERR);
            }
        });
    } catch (e) {
        if (show_layer != 0) {
            layer.close(layer_index);
        }
    }

}

/**
 * 加载页面表格
 * @param para_json_obj 格式如下:
 * {
 *     layer_table_define_obj:layer创建的table对形象,
 *     layer_table_column_obj:[[表格样式]],
 *     ajax_url:Ajax 调用的url,
 *     ajax_json_data:ajax请求附带的参数
 *     dom_table_id:页面中dom对象的table id
 *     dom_bar_id:页面上方增删改查按钮,
 *     callback:表格加载完毕回调函数
 * }
 */
function initPageTableData(para_json_obj) {
    var table = para_json_obj.layer_table_define_obj;

    var tbJson = {
        elem: '#' + para_json_obj.dom_table_id,
        url: getAjaxRequestUrl(para_json_obj.ajax_url),
        method: 'POST',
        where: {'inParaJsonStr': JSON.stringify( para_json_obj.ajax_json_data)},
        toolbar: '#' + para_json_obj.dom_bar_id,
        response: {statusCode: 'S'},
        cols: para_json_obj.layer_table_column_obj,
        page: true,
        height: 'full-0',
        done: function(res, curr, count){
            para_json_obj.callback(res, curr, count);
        }
    }

    table.render(tbJson);
}

/**
 * 获取URL中指定参数的值
 * @param {Object} paramName
 */
function getURLParameter(paramName) { 
    paramValue = "", isFound = !1; 
    if (this.location.search.indexOf("?") == 0 && this.location.search.indexOf("=") > 1) { 
        arrSource = unescape(this.location.search).substring(1, this.location.search.length).split("&"), i = 0; 
        while (i < arrSource.length && !isFound) arrSource[i].indexOf("=") > 0 && arrSource[i].split("=")[0].toLowerCase() == paramName.toLowerCase() && (paramValue = arrSource[i].split("=")[1], isFound = !0), i++ 
    } 
    return paramValue == "" && (paramValue = null), paramValue 
} 
