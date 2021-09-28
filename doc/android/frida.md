## `HashMap.put`代码定位


> Log.getStackTraceString(new Throwable())

该方法可以打印当前所在的代码行的堆栈信息，现在通过`frida`主动调用的方式来实现

```javascript
    function statckflow_display(){
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }
```


> java.util.HashMap

安卓开发常用`HashMap`来保存一些加密信息键值对，可以去hook `put`方法去获取到加密信息键值。然后主动调用`statckflow_display`方法打印当前堆栈调用

```javascript
    Java.perform(function(){
        let hashMap = Java.use("java.util.HashMap");
        hashMap.put.implementation = function(key,value){
            console.log("hashMap.put =>",key,value);
            return this.put(key,value)
        }
    })
```
注入frida脚本，找到hook关键键值对信息
```bash
    hashMap.put => sound_effects_enabled 1
    hashMap.put => zh_CN_#Hans java.lang.Object@4cc2bd5
    hashMap.put => zh_CN_#Hans java.lang.Object@4cc2bd5
    hashMap.put => zh_CN_#Hans java.lang.Object@4cc2bd5
    hashMap.put => username 15926223463
    hashMap.put => userPwd 12345678
    hashMap.put => equtype ANDROID
    hashMap.put => loginImei Android358123090192582
    hashMap.put => timeStamp 1632764169832
    hashMap.put => sign 7AD8E9519124E820F78D6E8D8A353404
```
对代码稍作修改，去打印关键信息的堆栈调用链
```javascript
Java.perform(function(){
    function statckflow_display(){
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }
    let hashMap = Java.use("java.util.HashMap");
    hashMap.put.implementation = function(key,value){
        if(key.equals("userPwd")){
            console.log("hashMap.put =>",key,value);
            statckflow_display()
        }
        return this.put(key,value)
    }
})
```
堆栈信息获取结果：
```bash
hashMap.put => userPwd 12345678
java.lang.Throwable
	at java.util.HashMap.put(Native Method)
	at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:128)
	at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
	at android.view.View.performClick(View.java:6597)
	at android.view.View.performClickInternal(View.java:6574)
	at android.view.View.access$3100(View.java:778)
	at android.view.View$PerformClick.run(View.java:25885)
	at android.os.Handler.handleCallback(Handler.java:873)
	at android.os.Handler.dispatchMessage(Handler.java:99)
	at android.os.Looper.loop(Looper.java:193)
	at android.app.ActivityThread.main(ActivityThread.java:6718)
	at java.lang.reflect.Method.invoke(Native Method)
	at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
	at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```
通过jadx工具反编译-搜索`com.dodonew.online.ui.LoginActivity`定位到`128`行代码处
```java
    private void login(String userName, String pwd) {
        this.DEFAULT_TYPE = new TypeToken<RequestResult<User>>() {
        }.getType();
        this.para.clear();
        this.para.put("username", userName);
        this.para.put("userPwd", pwd);
        if (TextUtils.isEmpty(DodonewOnlineApplication.devId)) {
            DodonewOnlineApplication.devId = Utils.getDevId(DodonewOnlineApplication.getAppContext());
        }
        this.para.put("equtype", Config.equtype);
        this.para.put("loginImei", "Android" + DodonewOnlineApplication.devId);
        requestNetwork("user/login", this.para, this.DEFAULT_TYPE);
    }

    private void requestNetwork(final String cmd, Map<String, String> para2, Type type) {
        showProgress();
        this.request = new JsonRequest(this, "http://api.dodovip.com/api/" + cmd, "", new Response.Listener<RequestResult>() {
            public void onResponse(RequestResult requestResult) {
                if (!requestResult.code.equals(a.e)) {
                    LoginActivity.this.showToast(requestResult.message);
                } else if (cmd.equals("user/login")) {
                    DodonewOnlineApplication.loginUser = requestResult.data;
                    DodonewOnlineApplication.loginLabel = "mobile";
                    Utils.saveJson(LoginActivity.this, DodonewOnlineApplication.loginLabel, Config.LOGINLABEL_JSON);
                    LoginActivity.this.intentMainActivity();
                }
                LoginActivity.this.dissProgress();
            }
        }, this, type);
        this.request.addRequestMap(para2, 0);
        DodonewOnlineApplication.addRequest(this.request, this);
    }
```
可以看出`this.para`是符合hook关键键值对信息的准确性，然后顺藤摸瓜找到`this.request.addRequestMap(para2, 0);`。后面的协议加密流程不做讲解，现阶段只论关键代码定位。

## `ArrayList.add`代码定位

>java.util.ArrayList

前面说到hook `HashMap.put`方法来定位到指定关键信息，打印调用栈帧。现在hook `ArrayList.add`来关键信息，流程大致都一样。
```javascript
Java.perform(function(){
    var arrayList = Java.use("java.util.ArrayList");
    function statckflow_display(){
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }
    arrayList.add.overload("java.lang.Object").implementation = function(ele){
        // if(ele.equals("username=15926223463")){
        if(ele == "username=15926223463"){
            console.log("arrayList.add =>",ele);
            statckflow_display()
        }
        console.log("arrayList.add =>",ele);
        return this.add(ele);
    };
    arrayList.add.overload("int","java.lang.Object").implementation = function(index,ele){
            console.log("arrayList.add =>",index,ele);
            return this.add(index,ele);
    };
}
```
调用堆栈结果如下：
```
java.lang.Throwable
	at java.util.ArrayList.add(Native Method)
	at com.dodonew.online.http.RequestUtil.paraMap(RequestUtil.java:71)
	at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:112)
	at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
	at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
	at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
	at android.view.View.performClick(View.java:6597)
	at android.view.View.performClickInternal(View.java:6574)
	at android.view.View.access$3100(View.java:778)
	at android.view.View$PerformClick.run(View.java:25885)
	at android.os.Handler.handleCallback(Handler.java:873)
	at android.os.Handler.dispatchMessage(Handler.java:99)
	at android.os.Looper.loop(Looper.java:193)
	at android.app.ActivityThread.main(ActivityThread.java:6718)
	at java.lang.reflect.Method.invoke(Native Method)
	at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
	at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```
HOOK `ArrayList.add(ele)`方法时，通过使用`ele.equals()`方法容易导致App崩溃，具体原因尚未得知。


## `TextUtils.isEmpty`代码定位

>android.text.TextUtils

```javascript
Java.perform(function(){
    var textUtils = Java.use("android.text.TextUtils");
    textUtils.isEmpty.implementation = function(data){
        if(data == "2v+DC2gq7RuAC8PE5GZz5wH3/y9ZVcWhFwhDY9L19g9iEd075+Q7xwewvfIN0g0ec/NaaF43/S0="){
            console.log("textUtils.isEmpty",data);
            statckflow_display()
        }
        return this.isEmpty(data);
    }
})
```
调用堆栈结果如下：
```
java.lang.Throwable
        at android.text.TextUtils.isEmpty(Native Method)
        at com.dodonew.online.http.RequestUtil.decodeDesJson(RequestUtil.java:169)
        at com.dodonew.online.http.JsonRequest.parseNetworkResponse(JsonRequest.java:82)
        at com.android.volley.NetworkDispatcher.run(NetworkDispatcher.java:121)
```


## `String.trim`代码定位

> java.lang.String

```javascript
    Java.perform(function(){
        if("PKCS5Padding" == this){
            statckflow_display()
        }
        console.log(this);
        return this.trim();
    })
```
调用堆栈结果如下：
```
java.lang.Throwable
        at java.lang.String.trim(Native Method)
        at javax.crypto.Cipher.tokenizeTransformation(Cipher.java:430)
        at javax.crypto.Cipher.createCipher(Cipher.java:723)
        at javax.crypto.Cipher.getInstance(Cipher.java:619)
        at com.dodonew.online.util.DesSecurity.InitCipher(DesSecurity.java:40)
        at com.dodonew.online.util.DesSecurity.<init>(DesSecurity.java:23)
        at com.dodonew.online.http.RequestUtil.encodeDesMap(RequestUtil.java:128)
        at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:113)
        at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
        at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
        at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
        at android.view.View.performClick(View.java:6597)
        at android.view.View.performClickInternal(View.java:6574)
        at android.view.View.access$3100(View.java:778)
        at android.view.View$PerformClick.run(View.java:25885)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)

```
## `Log.w`代码定位

>android.util.Log

使用`adb logcat`查看App后台日志发现了两条关键log请求日志信息
```
2021-09-28 23:18:25.758 9418-9418/? W/yang: {"equtype":"ANDROID","loginImei":"Android358123090192582","sign":"C30C359F968F39C1FD9DAA8B7D65405D","timeStamp":"1632842305757","userPwd":"1234567","username":"15926223463"}   result

2021-09-28 23:18:25.841 9418-9435/? W/yang: {"code":-1,"message":"账号或密码错误","data":{}}
```
从上面可以观察出两条日志信息是跟登录有关数据，不用多说上HOOK代码

```javascript
Java.perform(function(){
    var log_ = Java.use("android.util.Log");
    log_.w.overload('java.lang.String', 'java.lang.String').implementation = function(tagName,message){
        console.log(tagName,message);
        statckflow_display();
        return this.w(tagName,message);
    }
})
```
调用堆栈结果如下：
```
yang {"equtype":"ANDROID","loginImei":"Android358123090192582","sign":"8921A89B281A267168711D483567C56A","timeStamp":"1632843083552","userPwd":"1234567","username":"15926223463"}   result
java.lang.Throwable
        at android.util.Log.w(Native Method)
        at com.dodonew.online.http.RequestUtil.paraMap(RequestUtil.java:82)
        at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:112)
        at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
        at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
        at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
        at android.view.View.performClick(View.java:6597)
        at android.view.View.performClickInternal(View.java:6574)
        at android.view.View.access$3100(View.java:778)
        at android.view.View$PerformClick.run(View.java:25885)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858
```
## `EditText.getText`代码定位

>android.widget.EditText

通过HOOK 安卓组件输入框`EditText.getText`，来定位打印堆栈信息，从而找到相关的代码信息

```js
    var widget_edittest = Java.use("android.widget.EditText");
    widget_edittest.getText.overload().implementation = function(){
        var result = this.getText();
        result = Java.cast(result,Java.use("java.lang.CharSequence"))
        console.log(result.toString());
        return result
    }
```
感觉作用不是很大。这里涉及到frida Java类型强转方法`Java.cast`
调用堆栈结果如下：
```
java.lang.Throwable
        at android.widget.EditText.getText(Native Method)
        at android.widget.EditText.getText(EditText.java:74)
        at android.widget.TextView.getSelectionEnd(TextView.java:9343)
        at android.widget.Editor.onDraw(Editor.java:1758)
        at android.widget.TextView.onDraw(TextView.java:7229)
        at android.view.View.draw(View.java:20207)
        at android.view.View.updateDisplayListIfDirty(View.java:19082)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ViewGroup.recreateChildDisplayList(ViewGroup.java:4317)
        at android.view.ViewGroup.dispatchGetDisplayList(ViewGroup.java:4290)
        at android.view.View.updateDisplayListIfDirty(View.java:19042)
        at android.view.ThreadedRenderer.updateViewTreeDisplayList(ThreadedRenderer.java:686)
        at android.view.ThreadedRenderer.updateRootDisplayList(ThreadedRenderer.java:692)
        at android.view.ThreadedRenderer.draw(ThreadedRenderer.java:801)
        at android.view.ViewRootImpl.draw(ViewRootImpl.java:3318)
        at android.view.ViewRootImpl.performDraw(ViewRootImpl.java:3122)
        at android.view.ViewRootImpl.performTraversals(ViewRootImpl.java:2481)
        at android.view.ViewRootImpl.doTraversal(ViewRootImpl.java:1463)
        at android.view.ViewRootImpl$TraversalRunnable.run(ViewRootImpl.java:7190)
        at android.view.Choreographer$CallbackRecord.run(Choreographer.java:949)
        at android.view.Choreographer.doCallbacks(Choreographer.java:761)
        at android.view.Choreographer.doFrame(Choreographer.java:696)
        at android.view.Choreographer$FrameDisplayEventReceiver.run(Choreographer.java:935)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```

## `Collections.sort`代码定位

> java.util.Collections

如果反编译app源代码中有对List接口实现的类进行`sort`排序，我们可以通过hook该方法找到对应的堆栈信息
```js
Java.perform(function () {
    var collections = Java.use("java.util.Collections");
    collections.sort.overload('java.util.List').implementation = function (_list) {
        _list = Java.cast(_list, Java.use("java.util.ArrayList"))
        statckflow_display()
        console.log("collections.sort(a) =>", _list + "");
        return this.sort(_list)
    };
    collections.sort.overload('java.util.List', 'java.util.Comparator').implementation = function (_list, comparator) {
        _list = Java.cast(_list, Java.use("java.util.ArrayList"))
        statckflow_display()
        console.log("collections.sort(a,b) =>", _list + "", comparator);
        return this.sort(_list, comparator)
    }
})
```
HOOK出来的关键结果如下
```log
collections.sort(a) => [timeStamp=1632847588877, loginImei=Android358123090192582, equtype=ANDROID, userPwd=12345678, username=15926223464]
java.lang.Throwable
        at java.util.Collections.sort(Native Method)
        at com.dodonew.online.http.RequestUtil.paraMap(RequestUtil.java:73)
        at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:112)   
        at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
        at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
        at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)       
        at android.view.View.performClick(View.java:6597)
        at android.view.View.performClickInternal(View.java:6574)
        at android.view.View.access$3100(View.java:778)
        at android.view.View$PerformClick.run(View.java:25885)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```


## `JSONObject.getString & JSONObject.put`代码定位 

> org.json.JSONObject

绝大多数安全性较高的请求携带的数据去提交POST，都会对起JSON数据格式进行对称加密处理。所以当下去HOOK相关的JSON库的方法是很有必要的。闲话不多说上代码。

```js
Java.perform(function(){
    var JSONObject = Java.use("org.json.JSONObject");
    JSONObject.getString.overload('java.lang.String').implementation = function(a){
        console.log("JSONObject.getString=>",a);
        
        return this.getString(a);
    }
    JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(a,b){
        console.log("JSONObject.put=>",a,b);
        statckflow_display()
        return this.put(a,b);
    }
})
```
调用堆栈结果如下：
```log
JSONObject.put=> Encrypt NIszaqFPos1vd0pFqKlB42Np5itPxaNH//FDsRnlBfgL4lcVxjXii/C1s6R3+T7ASlI9/uryHexe
uBya62m+egbnh+7Fpx2H3u+3Zae6J4FXT9DD+zA47zdFZ1JVWq/e/BpFm7N2j3bQWgSYZjpvzKH7
FdBxXfDsBYTCu+NYz/gzMrLjUmhD+MxvMk7kaHpRwmvhm9NSQVWIKPQr5525psGcsJgqa25VGzay
rizzAek=

java.lang.Throwable
        at org.json.JSONObject.put(Native Method)
        at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:116)
        at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
        at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
        at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
        at android.view.View.performClick(View.java:6597)
        at android.view.View.performClickInternal(View.java:6574)
        at android.view.View.access$3100(View.java:778)
        at android.view.View$PerformClick.run(View.java:25885)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```

## `Toast.show`代码定位

> android.widget.Toast

在安卓界面之中提交数据时，有时候会碰到Toast控件弹出加密或登录状态信息。这个时候去HOOK `Toast.show`或许是一个不错的方法。
```js
Java.perform(function(){
    var Toast = Java.use("android.widget.Toast");
    Toast.show.overload().implementation = function(){
        statckflow_display()
        return this.show();
    }
})
```
调用堆栈结果如下：
```log
java.lang.Throwable
        at android.widget.Toast.show(Native Method)
        at com.dodonew.online.util.ToastMsg.showToastMsg(ToastMsg.java:66)
        at com.dodonew.online.base.ProgressActivity.showToast(ProgressActivity.java:81)
        at com.dodonew.online.ui.LoginActivity$2.onResponse(LoginActivity.java:156)
        at com.dodonew.online.ui.LoginActivity$2.onResponse(LoginActivity.java:145)
        at com.dodonew.online.http.JsonBaseRequest.deliverResponse(JsonBaseRequest.java:25)
        at com.android.volley.ExecutorDelivery$ResponseDeliveryRunnable.run(ExecutorDelivery.java:99)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```

## `Base64.encodeToString`代码定位

> android.util.Base64

安卓自带Base64的编码库，查找位置时犯困时，去hook这个重点检查对。

```js
Java.perform(function(){
    var base64 = Java.use("android.util.Base64");
    base64.encodeToString.overload('[B', 'int').implementation = function(obj,num){
        console.log(JSON.stringify(obj) + "",num)
        let res = this.encodeToString(obj,num)
        console.log("base64.encodeToString =>",res)
        statckflow_display()
        return res
    }
})
```
调用堆栈结果如下：
```log
base64.encodeToString => NIszaqFPos1vd0pFqKlB42Np5itPxaNH//FDsRnlBfgL4lcVxjXii/C1s6R3+T7ASlI9/uryHexe
uBya62m+ejtGBSEJ/905/B1hK+6qCx+qXV00ibQGgFUmzYPHfSiRg8TKXezBQRXBF4tgmB0/7Pic
r+Lv8k4GTwx0eDZ5+flfvYnX6GBivVCPdQ8nWAfl2wvr573wffgN7KIvpcYkFhfBW6OR/lBPS2Ta
8g89ZmA=

java.lang.Throwable
        at android.util.Base64.encodeToString(Native Method)
        at com.dodonew.online.util.DesSecurity.encrypt64(DesSecurity.java:49)
        at com.dodonew.online.http.RequestUtil.encodeDesMap(RequestUtil.java:129)
        at com.dodonew.online.http.JsonRequest.addRequestMap(JsonRequest.java:113)
        at com.dodonew.online.ui.LoginActivity.requestNetwork(LoginActivity.java:161)
        at com.dodonew.online.ui.LoginActivity.login(LoginActivity.java:134)
        at com.dodonew.online.ui.LoginActivity.onClick(LoginActivity.java:103)
        at android.view.View.performClick(View.java:6597)
        at android.view.View.performClickInternal(View.java:6574)
        at android.view.View.access$3100(View.java:778)
        at android.view.View$PerformClick.run(View.java:25885)
        at android.os.Handler.handleCallback(Handler.java:873)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loop(Looper.java:193)
        at android.app.ActivityThread.main(ActivityThread.java:6718)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:493)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:858)
```

## `String.getBytes`代码定位

> java.lang.String

```js
    Java.perform(function(){
        var str = Java.use("java.lang.String");
        str.getBytes.overload('java.lang.String').implementation = function(obj){
            let _tmp = this.getBytes(obj);
            let string_ = str.$new(_tmp);
            console.log("string_ => ",string_);
            return _tmp
        }
        str.getBytes.overload().implementation = function(){
            let _tmp = this.getBytes();
            let string_ = str.$new(_tmp);
            console.log("string_ => ",string_);
            
            return _tmp
        }
    })
```
调用堆栈结果如下：
```log
java.lang.Throwable
        at java.lang.String.getBytes(Native Method)
        at android.util.Base64.decode(Base64.java:118)
        at com.dodonew.online.util.DesSecurity.decrypt64(DesSecurity.java:54)
        at com.dodonew.online.http.RequestUtil.decodeDesJson(RequestUtil.java:174)
        at com.dodonew.online.http.JsonRequest.parseNetworkResponse(JsonRequest.java:82)
        at com.android.volley.NetworkDispatcher.run(NetworkDispatcher.java:121)
```