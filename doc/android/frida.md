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
HOOK出来的关键结果如下
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
HOOK出来的关键结果如下
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
HOOK出来的关键结果如下
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
HOOK出来的关键结果如下
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

