某加密到牙齿的APP数据加密分析
----

在某特上关注了一点乱七八糟的东西，然后就看到了这么一款app。无聊业余时间的时候爬取了一些福利app的数据，于是就想顺便看下这个东西的数据是否也可以爬取。\  
![total](screenshots/tatal.jpg)
目前一共爬取了10w+数据，我准备等哪天出个福利网站数据分析报告。  

### 图片解析  

----

习惯性的打开HttpCanary抓包，目前一切正常。  
![httpcanary](screenshots/httpcanary.jpg)  
数据都能获取到，既然要爬数据，肯定是要能够看到图片，这个是最起码的。  图片链接如下： https://ssimg.bdxxo.cn/tv_adult/avid5c33013611e90.jpg?k=0bf5566b1e365d4f0cf78f566269e769&t=1593571053  
看到后面的k和t，忽然觉得这个东西可能没这么简单，应该是服务器进行访问校验了，先不管这个，直接访问下看看。   
![encrypt_image](screenshots/encrypt_image.jpg)  
这个，尼玛，厉害了。带着key和token访问直接返回了个黑窗口（如果时间超过了链接中的t参数表示的时间，那么直接就403了）。  
把图片下载下来，拉入010，果然是加密处理了。  
![010en](screenshots/010en.jpg)  
没有找到图片文件的文件头，所以浏览器或者图片查看器也就没有办法解析这个图片。  
如何解析图片，那就要从apk入手进行分析了。最终在package net.idik.lib.cipher.so;下面找到了可疑的key和iv：
```javascript
public static final String dbImgKey() {
        return CipherCore.get("29993fb387b37c932b56fd54b130e0c6");
    }

    public static final String decodeImgIv() {
        return CipherCore.get("f3d9434408e52778164db2214e3a0a22");
    }

```
通过交叉引用，可以定位到图片解密代码位于com.ilulutv.fulao2.other.g.b：
```javascript
    public static byte[] b(byte[] arg3, byte[] arg4, String arg5) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher v0 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        v0.init(2, new SecretKeySpec(arg3, "AES"), new IvParameterSpec(arg4));
        return v0.doFinal(Base64.decode(arg5, 2));
    }
```
配置jeb调试器，如果不修改ro.debuggable 直接附加进程，会出现下面的错误信息：  
![notice](screenshots/notification.jpg)  
确定之后就直接失败了：  
![error](screenshots/error.jpg)  
修改安卓的ro.debuggable属性可以通过magisk 或者mprop([https://bbs.pediy.com/thread-215311.htm]),当然也有其他的办法，修改boot.img等等。不幸的是，我在夜神模拟器上安装magisk之后，卡在了检查更新上，没有办法继续安装。知道原因的还望不吝赐教。  
![magisk](screenshots/magisk.jpg)  
另外一个办法，就是通过mprop修改，下载之后，直接运行对应的bat文件即可。  
![mprop](screenshots/mprop.jpg)  
需要注意的是，运行完脚本之后需要重新打开apk，否则依旧无法进行附加。  
附加之后，向下滚动页面加载内容。此时断点就断下来了。  
![brakpoint](screenshots/breakpoint.jpg)  
单步执行到00000014  invoke-direct       SecretKeySpec-><init>([B, String)V, v1, p0, v2 这一行就可以看到具体的key和iv的值了。  
默认的jeb的局部变量类型全部为int，可以根据代码来修改变量类型，这里两个参数的类型都是B[,修改之后就可以看到具体的数值了， 如下：  
![image_key_iv](screenshots/iamge_key_iv.jpg)  
 比较蛋疼的一点是，jeb直接复制的变量的值是下面的格式：  
 ```javascript
array@7671 (type=[B)
[-78(FFFFFFFFFFFFFFB2h), -13(FFFFFFFFFFFFFFF3h), -124(FFFFFFFFFFFFFF84h), 40(28h), 102(66h), -7, 88(58h), 61(3Dh), 30(1Eh), -50(FFFFFFFFFFFFFFCEh), 97(61h), -60(FFFFFFFFFFFFFFC4h), -32(FFFFFFFFFFFFFFE0h), 85(55h), -62(FFFFFFFFFFFFFFC2h), 85(55h)]
```
鉴于net.idik.lib.cipher.so的目录下的key比较多，并且key包含不可打印字符，直接复制数值也比较蛋疼。  
此时frida hook就派上用场了：  
```javascript
var base64 = Java.use('android.util.Base64');
  var aes = Java.use('com.ilulutv.fulao2.other.g.b');
    // 图片加密处理
    aes.b.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("Image_key:"+k);
        send(base64.encodeToString(k, 0))
        send("Image_iv:"+iv);
        send(base64.encodeToString(iv, 0))
        return this.b(k, iv, source_string);
    };
```
由于该函数的key和为是一个byte数据，所以直接通过send函数发送。接收到的数据是个Image_iv:[object Object] 无法正常显示，所以上面的代码对数据进行了base64编码之后发送。  
实际接收到的数据为：  
```batch
[*] ===========================override image a begin ===========================
[*] Image_key:[object Object]
[*] svOEKGb5WD0ezmHE4FXCVQ==

[*] Image_iv:[object Object]
[*] 4B7eYzHTevzHvgVZfWVNIg==

[*] ===========================override image a end ===========================
```
有了这两个数据就可以去解密图片内容了：  
```python
def aes_decrypt_raw(key, data, ivs):
    encodebytes = data
    cipher = AES.new(key, AES.MODE_CBC, ivs)
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    return text_decrypted

def decode_image():
    f = open(r"H:\PyCharmProjects\frida_test\avid5c33013611e90.jpg", 'rb')  # 二进制读
    b = f.read()
    f.close()
    # array@7687 (type=[B)
    image_key_base64 = bytes('svOEKGb5WD0ezmHE4FXCVQ==', encoding='utf8')  # 图片解密key
    image_key = base64.decodebytes(image_key_base64)
    print(image_key)
    iv = base64.decodebytes(bytes('4B7eYzHTevzHvgVZfWVNIg==', encoding='utf8'))  # 图片解密iv
    de = aes_decrypt_raw(image_key, b, iv)
    f = open(r"H:\PyCharmProjects\frida_test\avid5c33013611e90_decode.jpg", 'wb')  
    f.write(de)
    f.close()
```
解密之后的图片内容：  
![decrypt image](screenshots/decrypt_image.jpg)  
鉴于图片内容比较暴力，这里就不展示了，感兴趣的自己去解析即可。到这里图片的内容算是处理完成了。  


### 数据接口分析  

----

图片可以查看之后，主要的目标是要爬取数据，那么数据来源就很关键。通过接口格式猜测，请求视频列表的接口应该是https://api-al.vipmxmx.cn/v1/videos/menu/0?payload=D%2FPrh8wy4ODFaRYJGqhokg%3D%3D.9VP71aDIZgmZFc6X3l%2BfPoETfpXd4Jt%2BTN49ks4edK8vgtl1XHAvEPzA9EC7mTBjU59pMvWwASxSl9nUQA%2BpzTqjNk0hzAO%2FTMZ6fBkTwtJ4S11%2F4RABwCQVs%2Flk5VuDxcF6DUYuV7XnKO%2FI25woZXbONYp47i%2F1h5OGcW3I91LfJ4G8c0HZI7kli5RLbgn2Rvqt6Jk897dHkmnj4n2tbhoS3nC%2Bp3hxauGMGH2%2Byl1kah6ZGKL%2FarjRwBKR8%2Bbv7XCApO%2BWMrjwxMdJBZjxnV6obnCF5KqYGtauUC5ZN31AjG%2F7ilKr7PGYqu2b%2FrSqpvPXWBizmuw9JF1e%2BnC41vj6bOBXx4swAHsBFFK64C46byIxosDNHN4i5dofoaQH
请求接口比较简洁，应该是把所有的参数都放到了payload下面  
![list_request](screenshots/list_request.jpg)  
返回的数据比较复杂，头部包含了大量的信息:  
![list_response_header](screenshots/list_response_header.jpg)  
并且返回的数据进行了加密:  
![list_response_text](screenshots/list_response_text.jpg)  
要想通过接口访问数据，那么就要解析请求数据，解密返回的数据。 
通过参数的payload最终可以定位到以下代码：  
```javascript
private void d() {  // 页面请求函数
        String v0_3;
        try {
            this.j.put("path", this.o.substring(1));
            this.j.put("timestamp", String.valueOf(System.currentTimeMillis() / 1000L));
            String v0_1 = new Gson().toJson(this.j);
            byte[] v1 = Base64.decode(CipherClient.apiEncryptParamsKey(), 0);
            // 下面一行jeb给解析成了一个数组，实际在代码中的是个随机函数。
            byte[] v2 = new byte[]{-73, 0x3F, 110, -34, 0xE1, -56, -7, -4, 88, 0x8E, 101, 38, -92, 21, -61, 17};
            // 下面是aes加密，如果要知道加密的key和iv只需要hook b.c函数即可。
            String v0_2 = b.c(v1, v2, v0_1);
            int v1_1 = this.l;
            if(v1_1 == 81002) {
            label_39:
                // b.a base64编码。v2为加密的iv， 通过base64编码iv之后 使用.将iv和加密后的请求数据链接。
                v0_3 = b.a(v2) + "." + v0_2;
            }
            else {
                if(this.l == 81004) {
                    goto label_39;
                }
                // b.g 为urlencoder函数
                v0_3 = b.g(b.a(v2) + "." + v0_2);
            }

            this.j.clear();
            this.j.put("payload", v0_3);
        }
        catch(NoSuchAlgorithmException v0) {
            v0.printStackTrace();
        }
    }
```
通过frida hook 对b.c函数进行hook:  
```javascript
// 接口加密处理
    aes.c.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override c begin ===========================")
        send("key:"+k);
        send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var res = this.c(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override c end ===========================")
        return res;
    };
```
所以如果要进行接口加密，那么只需要知道加密的key即可，以为通过上面的代码分析可以知道，iv是一个随机函数生成的长度为16的数组。如果要想模拟的真实一点可以自己写一个随机函数，当然也可以直接使用jeb解析出来的数组去请求也是ok的。 捕获到的数据如下;  
```batch
[*] ===========================override c begin ===========================
[*] key:[object Object]
[*] euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=

[*] iv:[object Object]
[*] D/Prh8wy4ODFaRYJGqhokg==

[*] source_string:
[*] {"timestamp":"1593572575","order":"time","video_type":"long","type":"uncover","page":"6","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/menu/0"}
[*] result:
[*] 9VP71aDIZgmZFc6X3l+fPoETfpXd4Jt+TN49ks4edK8vgtl1XHAvEPzA9EC7mTBjU59pMvWwASxSl9nUQA+pzTqjNk0hzAO/TMZ6fBkTwtJ4S11/4RABwCQVs/lk5VuDxcF6DUYuV7XnKO/I25woZXbONYp47i/1h5OGcW3I91LfJ4G8c0HZI7kli5RLbgn2Rvqt6Jk897dHkmnj4n2tbhoS3nC+p3hxauGMGH2+yl1kah6ZGKL/arjRwBKR8+bv7XCApO+WMrjwxMdJBZjxnV6obnCF5KqYGtauUC5ZN31AjG/7ilKr7PGYqu2b/rSqpvPXWBizmuw9JF1e+nC41vj6bOBXx4swAHsBFFK64C46byIxosDNHN4i5dofoaQH
[*] ===========================override c end ===========================
```
将euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs= base64 decode之后即可获得加密用的key。  
有了这些数据，那么就可以发送请求了， 测试代码如下：  
```python
def new_video_get_test():
    request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    # request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    request_iv = base64.decodebytes(bytes('HTpKwS4MVfB2pktFSGRzvw==', encoding='utf8'))

    ss = '{"timestamp":"' + str(int(
        time.time())) + '","order":"time","video_type":"long","type":"uncover","page":"1","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/videos/menu/0"}'

    ds = AES_Encrypt_raw(request_key, ss, request_iv)
    print(ds)
    payload = 'HTpKwS4MVfB2pktFSGRzvw==.' + ds
    base_url = 'https://api-tc.bjsongmoxuan.cn/v1/videos/menu/0?payload=' + urllib.parse.quote(payload)

    print(base_url)
    resp = requests.get(base_url)
    print(resp.text)
```
此时虽然已经能够发送请求了，但是返回的数据是加密的，如果要想获取直接可用的数据，那么就需要对返回的数据进行解密。  
通过层层分析，可以定位到响应数据的解密函数为：  
```javascript
    public static String a(String arg2, String arg3, String arg4) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {  // 请求解密函数
        String v2 = b.e(arg2);  // MD5加密
        return b.a(new IvParameterSpec(arg3.getBytes(StandardCharsets.UTF_8)), new SecretKeySpec(v2.getBytes(StandardCharsets.UTF_8), "AES"), arg4);
    }
```
同样对对该函数进行hook:
```javascript
// 接口解密处理
    aes.a.overload( "java.lang.String",  "java.lang.String", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override a begin ===========================")
        send("key:"+k);
        //send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        //send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var new_key = this.e(k);
        send("new key:" + new_key);
        var res = this.a(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override a end ===========================")
        return res;
    };
```
获取数据:  
```batch
[*] ===========================override a begin ===========================
[*] key:fe34dd6bbd3020c2fb69abe73b5b973c
[*] iv:ce9337500ee76035
[*] source_string:
[*] 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
[*] result:
[*] {"status":{"code":200,"message":"success"},"response":{"videos":[{"video_id":"62754","video_title":"清纯模特丽丽第二弹! 多姿势不间断各种大战表情超诱人","actor":"素人","thumb":"\/tv_adult\/avid5aa739d33cb71.jpg?k=3c31a0b2eb0c7f27f2bba952492dd7f4&t=1593573476","cover":"\/tv_adult\/avid5aa739d33cb71.jpg?k=3c31a0b2eb0c7f27f2bba952492dd7f4&t=1593573476","upload_date":1593356402,"release_date":-1,"video_duration":3660,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"112902","video_title":" 姑娘胯下含三次，胯界妹妹的中出日记！ (FC2-PPV-1387608)","actor":"素人","thumb":"\/tv_adult\/avid5ed2ca1c2f19.jpg?k=232d13e7da07b264a567fc64c6a52f64&t=1593573476","cover":"\/tv_adult\/avid5ed2ca1c2f19.jpg?k=232d13e7da07b264a567fc64c6a52f64&t=1593573476","upload_date":1593354601,"release_date":-1,"video_duration":2940,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"78220","video_title":"想用一根鸡巴把你操爆~隔着黑丝袜也可以意淫~","actor":"素人","thumb":"\/tv_adult\/avid5d222d7fd97b.jpg?k=14a0f7232819dc45398878303df06c58&t=1593573476","cover":"\/tv_adult\/avid5d222d7fd97b.jpg?k=14a0f7232819dc45398878303df06c58&t=1593573476","upload_date":1593352801,"release_date":-1,"video_duration":1080,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"64852","video_title":"秀人网嫩模龙泽美曦宾馆与土豪援交！被玩到尖叫 汁液狂流","actor":"素人","thumb":"\/tv_adult\/avid5ba324d210218.jpg?k=19cccb60309e56419e1badebfa3a70bc&t=1593573476","cover":"\/tv_adult\/avid5ba324d210218.jpg?k=19cccb60309e56419e1badebfa3a70bc&t=1593573476","upload_date":1593351002,"release_date":-1,"video_duration":1260,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"106135","video_title":" 把你的淫穴封印解除！肉棒喷射！ (FC2-PPV-1171064)","actor":"素人","thumb":"\/tv_adult\/avid5e85d66d550c5.jpg?k=bc16f5d607e9ef489653517a5fb0f43d&t=1593573476","cover":"\/tv_adult\/avid5e85d66d550c5.jpg?k=bc16f5d607e9ef489653517a5fb0f43d&t=1593573476","upload_date":1593349202,"release_date":-1,"video_duration":4320,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"67605","video_title":"大老板酒店大战会计人妻~白嫩人妻沙发上多体位啪啪啪~原来沙发也可以这样玩~汗流浃背的让人妻欲仙欲死~","actor":"素人","thumb":"\/tv_adult\/avid5c1b1372a5522.jpg?k=5384afc3267953deb7f7d41c03a79dda&t=1593573476","cover":"\/tv_adult\/avid5c1b1372a5522.jpg?k=5384afc3267953deb7f7d41c03a79dda&t=1593573476","upload_date":1593349202,"release_date":-1,"video_duration":1860,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"114552","video_title":" 揉奶让妹妹爽~蒙住眼默念三遍~大鸡鸡就会出现~(FC2-PPV-1406226)","actor":"素人","thumb":"\/tv_adult\/avid5eea4214dc755.jpg?k=bbac92d5ca89bbd75ae688aecfd68931&t=1593573476","cover":"\/tv_adult\/avid5eea4214dc755.jpg?k=bbac92d5ca89bbd75ae688aecfd68931&t=1593573476","upload_date":1593349200,"release_date":-1,"video_duration":3180,"main_tag":["抢先看"],"second_tag":["無"],"video_like":false},{"video_id":"114177","video_title":" 只爱无套中出学生妹! 偷拍流出! (FC2-PPV-1404586)","actor":"素人","thumb":"\/tv_adult\/avid5ee8b44d40e3f.jpg?k=d99838ff143cbb170f81ebf2064767c1&t=1593573476","cover":"\/tv_adult\/avid5ee8b44d40e3f.jpg?k=d99838ff143cbb170f81ebf2064767c1&t=1593573476","upload_date":1593349200,"release_date":-1,"video_duration":3000,"main_tag":["抢先看"],"second_tag":["無"],"video_like":false},{"video_id":"114164","video_title":" 上帝视角，就让我静静地看着你们爱爱。(FC2-PPV-1399814)","actor":"素人","thumb":"\/tv_adult\/avid5ee905927de28.jpg?k=d7ab66bad4efd85838cf1e59fc9fccc5&t=1593573476","cover":"\/tv_adult\/avid5ee905927de28.jpg?k=d7ab66bad4efd85838cf1e59fc9fccc5&t=1593573476","upload_date":1593349200,"release_date":-1,"video_duration":2520,"main_tag":["抢先看"],"second_tag":["無"],"video_like":false},{"video_id":"35978","video_title":"若妻の甘い母乳〜出产后色気が倍増しました〜            シリーズ特设","actor":"浅井りょう","thumb":"\/imgs\/thumb\/15\/1e7358c348.jpg?k=3ebed85b8a64b68b7590faff87e75dc6&t=1593573476","cover":"\/imgs\/cover\/f4\/1e7358c348.jpg?k=957ea9717cb70ab48aa6171ef64db082&t=1593573476","upload_date":1593347402,"release_date":-1,"video_duration":4080,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"82907","video_title":" 韩国演艺圈淫梦再现~长发正妹在床上摇啊摇~","actor":"素人","thumb":"\/tv_adult\/avid5d634f0b560ca.jpg?k=5e340777d78c21b8827219364f1a24b3&t=1593573476","cover":"\/tv_adult\/avid5d634f0b560ca.jpg?k=5e340777d78c21b8827219364f1a24b3&t=1593573476","upload_date":1593345601,"release_date":-1,"video_duration":180,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"78898","video_title":" 人妻到你家~换上年轻时的制服~仿佛回到18岁~","actor":"素人","thumb":"\/tv_adult\/avid5d2d9c10be5d4.jpg?k=6c1a46d1285ff22e633532356879e111&t=1593573476","cover":"\/tv_adult\/avid5d2d9c10be5d4.jpg?k=6c1a46d1285ff22e633532356879e111&t=1593573476","upload_date":1593343801,"release_date":-1,"video_duration":7020,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"62882","video_title":"女女相互交叠爱液交织！樱桃小嘴互相慰藉的样子很咸湿：双头龙也无法满足５","actor":"素人","thumb":"\/tv_adult\/avid5ab9f45f4b3ab.jpg?k=627467d21166d4b22decb72c025c3f90&t=1593573476","cover":"\/tv_adult\/avid5ab9f45f4b3ab.jpg?k=627467d21166d4b22decb72c025c3f90&t=1593573476","upload_date":1593342001,"release_date":-1,"video_duration":0,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"104541","video_title":"BOGA x BOGA 〜加藤えまが仆のプレイを褒め称えてくれる〜","actor":"加藤えま","thumb":"\/imgs\/thumb\/bf\/f17669efd4.jpg?k=fdfa6a29ab7a51f14c7fa6e85a5e6b2d&t=1593573476","cover":"\/imgs\/cover\/67\/f17669efd4.jpg?k=c972b8a9ff35f6b93703fb28623c1e56&t=1593573476","upload_date":1593340201,"release_date":1582905600,"video_duration":4020,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"63793","video_title":"  爱音真寻无修正三段流出! 不管穿甚么衣服下半身都被看光 (2)","actor":"素人","thumb":"\/tv_adult\/avid5b28b62b710c7.jpg?k=3ae54ab8d50d7ee60767820431397a06&t=1593573476","cover":"\/tv_adult\/avid5b28b62b710c7.jpg?k=3ae54ab8d50d7ee60767820431397a06&t=1593573476","upload_date":1593338403,"release_date":-1,"video_duration":2220,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"67405","video_title":"号称天然巨乳的酒店妹~就让我亲自鉴定鉴定~除了巨乳外~还有个会自己动的骚屁股~","actor":"素人","thumb":"\/tv_adult\/avid5c1323faa63f6.jpg?k=fa9b2eb5966971af92c024ed27cbd2c7&t=1593573476","cover":"\/tv_adult\/avid5c1323faa63f6.jpg?k=fa9b2eb5966971af92c024ed27cbd2c7&t=1593573476","upload_date":1593338402,"release_date":-1,"video_duration":480,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"112213","video_title":" SWAG vivibabe圣诞小淫娃的攻击！高颜直主播的性爱直播！","actor":"素人","thumb":"\/tv_adult\/avid5e9fb2317548c.jpg?k=13951fd22b50c11d74c83a25e7894612&t=1593573476","cover":"\/tv_adult\/avid5e9fb2317548c.jpg?k=13951fd22b50c11d74c83a25e7894612&t=1593573476","upload_date":1593336602,"release_date":-1,"video_duration":1500,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"61889","video_title":"才小小年纪就会用跳蛋 看似清纯却很变态","actor":"素人","thumb":"\/tv_adult\/avid5a54a731006f2.jpg?k=43ad150afb8c4986bb0286d38dda76ca&t=1593573476","cover":"\/tv_adult\/avid5a54a731006f2.jpg?k=43ad150afb8c4986bb0286d38dda76ca&t=1593573476","upload_date":1593334802,"release_date":-1,"video_duration":300,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"49463","video_title":"无尽的动漫电脑","actor":"素人","thumb":"\/tv_adult\/avid56fa62a27e469.jpg?k=618d9d8e265a7eb7b714540d1b404974&t=1593573476","cover":"\/tv_adult\/avid56fa62a27e469.jpg?k=618d9d8e265a7eb7b714540d1b404974&t=1593573476","upload_date":1593333003,"release_date":-1,"video_duration":60,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"94148","video_title":"Deeper Abigail Mac Work Week","actor":"无码素人","thumb":"\/imgs\/thumb\/97\/cc21b3f0c3.jpg?k=a259550f06a4fada200c6ff6284743be&t=1593573476","cover":"\/imgs\/cover\/7e\/cc21b3f0c3.png?k=2fb48d059e1bc512759326b1f545b914&t=1593573476","upload_date":1593333002,"release_date":-1,"video_duration":2040,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"101061","video_title":"痴汉快递员强奸了寂寞少妇!!买来的情趣用品直接派上用场!!","actor":"素人","thumb":"\/tv_adult\/avid5e3a416775e5b.jpg?k=e59c0b502f4f8f324502a6436222dbfb&t=1593573476","cover":"\/tv_adult\/avid5e3a416775e5b.jpg?k=e59c0b502f4f8f324502a6436222dbfb&t=1593573476","upload_date":1593331201,"release_date":-1,"video_duration":720,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"24280","video_title":"制服のまま焦らされて濡らされて","actor":"さくらみゆき","thumb":"\/imgs\/thumb\/d7\/349b1ae596.jpg?k=8bd8536a6a0ce729f9f713cdd2463b89&t=1593573476","cover":"\/imgs\/cover\/f9\/349b1ae596.jpg?k=0d688aed794dfa933d10bcc7cbb255f2&t=1593573476","upload_date":1593329402,"release_date":1525449600,"video_duration":3900,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"62034","video_title":" “我俩是不戴套，就是内射会怀孕的”淫女啪啪还大方自白 3","actor":"素人","thumb":"\/tv_adult\/avid5a6051db8fefa.jpg?k=dd588cc7b44a6c8b2c99a824c2a4510d&t=1593573476","cover":"\/tv_adult\/avid5a6051db8fefa.jpg?k=dd588cc7b44a6c8b2c99a824c2a4510d&t=1593573476","upload_date":1593327601,"release_date":-1,"video_duration":1980,"main_tag":[],"second_tag":["無"],"video_like":false},{"video_id":"26459","video_title":"マニアックマックス１ 北川弓香 – 长身スレンダー美女ダブル责め・Part１","actor":"北川弓香","thumb":"\/imgs\/thumb\/aa\/959ec2e919.jpg?k=6d9e86df1af7a252843949104ee7b274&t=1593573476","cover":"\/imgs\/cover\/07\/959ec2e919.jpg?k=cff025cfef43c87066bbfc82e7e48ef7&t=1593573476","upload_date":1593325802,"release_date":1490371200,"video_duration":1020,"main_tag":[],"second_tag":["無"],"video_like":false}],"total_results":20435,"page":6}}
[*] ===========================override a end ===========================
```
多次请求就会发现，key是固定的。但是iv却是变的。跟踪iv的数据来源，最终可以定位到
```javascript
 private void b(r arg5) {
        try {
            String v0_1 = b.a(arg5);
            if(v0_1 != null && !v0_1.isEmpty() && v0_1.getBytes(StandardCharsets.UTF_8) != null) {
                super.a(b.a(CipherClient.decodeKey(), v0_1, ((String)arg5.a())), this.m);
                return;
            }

            super.a(((String)arg5.a()), this.m);
        }
        catch(Exception v0) {
            Crashlytics.logException(new Exception(v0 + " blank " + arg5.c().toString() + " blank " + b.a(arg5)));
            super.a(905, String.valueOf(this.k));
        }
    }
  // b.a函数
    public static String a(r arg2) {
        s v2 = arg2.c();
        if(v2.a(CipherClient.headerIsEncryptKey()) != null) {
            return v2.a(CipherClient.headerIsEncryptKey()).equals(CipherClient.headerIsEncryptValue()) ? b.e(v2.a(CipherClient.headerKey())).substring(8, 24) : null;
        }

        return "";
    }
    // b.e 函数md5:
public static String e(String arg6) {
        try {
            MessageDigest v0 = MessageDigest.getInstance("MD5");
            v0.update(arg6.getBytes());
            byte[] v6_1 = v0.digest();
            StringBuilder v0_1 = new StringBuilder();
            int v2;
            for(v2 = 0; v2 < v6_1.length; ++v2) {
                String v3;
                for(v3 = Integer.toHexString(v6_1[v2] & 0xFF); v3.length() < 2; v3 = "0" + v3) {
                }

                v0_1.append(v3);
            }

            return v0_1.toString();
        }
        catch(NoSuchAlgorithmException v6) {
            v6.printStackTrace();
            return "";
        }
    }

```
为了简便期间，把上面的函数全部hook掉：
```javascript
// 接口解密处理
    aes.a.overload( "java.lang.String",  "java.lang.String", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override a begin ===========================")
        send("key:"+k);
        //send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        //send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var new_key = this.e(k);
        send("new key:" + new_key);
        var res = this.a(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override a end ===========================")
        return res;
    };
    aes.a.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override a bytes begin ===========================")
        send("key:"+k);
        send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var res = this.a(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override a bytes end ===========================")
        return res;
    };
    // md5函数
    aes.e.overload("java.lang.String").implementation = function(source_string){
        send("===========================override e begin ===========================")
        send("source_string:");
        send(source_string);
        var res = this.e(source_string);
        send('result:');
        send(res)
        send("===========================override e end ===========================")
        return res;
    };
    
    aes.a.overload("i.r").implementation = function(source_string){
        send("===========================override ia  begin ===========================")
        send("source_string:");
        send(source_string.toString());
        var res = this.a(source_string);
        send('result:');
        send(res)
        send("===========================override ia end ===========================")
        return res;
    };
    
    var iv_class = Java.use('e.s');
    iv_class.a.overload("java.lang.String").implementation = function(arg2){
        send("===========================iv test ===========================")
        send("source_string:");
        send(arg2);
        var res = this.a(arg2);
        send('result:');
        send(res)
        send("===========================iv test ===========================")
        return res;
    };
```
最终捕获到的数据如下：
```batch
[*] ===========================iv test ===========================
[*] ===========================override ia  begin ===========================
[*] source_string:
[*] Response{protocol=h2, code=200, message=, url=https://api-al.vipmxmx.cn/v1/videos/menu/0?payload=D%2FPrh8wy4ODFaRYJGqhokg%3D%3D.9VP71aDIZgmZFc6X3l%2BfPoETfpXd4Jt%2BTN49ks4edK8vgtl1XHAvEPzA9EC7mTBjU59pMvWwASxSl9nUQA%2BpzTqjNk0hzAO%2FTMZ6fBkTwtJ4S11%2F4RABwCQVs%2Flk5VuDxcF6DUYuV7XnKO%2FI25woZXbONYp47i%2F1h5OGcW3I91LfJ4G8c0HZI7kli5RLbgn2Rvqt6Jk897dHkmnj4n2tbhoS3nC%2Bp3hxauGMGH2%2Byl1kah6ZGKL%2FarjRwBKR8%2Bbv7XCApO%2BWMrjwxMdJBZjxnV6obnCF5KqYGtauUC5ZN31AjG%2F7ilKr7PGYqu2b%2FrSqpvPXWBizmuw9JF1e%2BnC41vj6bOBXx4swAHsBFFK64C46byIxosDNHN4i5dofoaQH}
[*] ===========================iv test ===========================
[*] source_string:
[*] X-App-Name
[*] result:
[*] app
[*] ===========================iv test ===========================
[*] ===========================iv test ===========================
[*] source_string:
[*] X-App-Name
[*] result:
[*] app
[*] ===========================iv test ===========================
[*] ===========================iv test ===========================
[*] source_string:
[*] X-VTag
[*] result:
[*] 1115682708
[*] ===========================iv test ===========================
[*] ===========================override e begin ===========================
[*] source_string:
[*] 1115682708
[*] result:
[*] d16ec86cce9337500ee76035d220d5a9
[*] ===========================override e end ===========================
[*] result:
[*] ce9337500ee76035
[*] ===========================override ia end ===========================
[*] ===========================override a begin ===========================
[*] key:fe34dd6bbd3020c2fb69abe73b5b973c
[*] iv:ce9337500ee76035
```
通过关联可以找到，iv的数据来源为X-VTag字段。所以请求之后从response header中取出X-VTag就可以解密数据了。
解密代码：
```python
response_headers = resp.headers
vtag = response_headers.get('x-vtag')
print(vtag)
i = md5(vtag)
print(i)
iv = i[8:24]
print(iv)
new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
dds = AES_Decrypt(new_key.encode('utf8'),
                  resp.text,
                  iv.encode('utf8'))
print(dds)
```
到这里接口的解密基本就完成了，可以获取app的视频基础信息了。

### 最后一米  

----

虽然现在视频列表数据已经有了，但是在视频信息中并没有播放地址。所以最后的工作就是获取视频的播放地址。继续抓包可以看到视频地址信息为：https://api.bdxxo.cn/v1/video/info/67432?payload=hAnCu1kQHy0hCrdZo4swYQ%3D%3D.BrHBQxJsA%2BevWaHMbZYNjOj6B7kDZk98IbSJ94j2EhhuMqcY9Rkv37MRgcYIzprPpxX0VJKcAc4sGAIG%2FtgQ3ZW%2FsnDAC%2FdUtA7Y2AfafmRsjxAhzazlbpOo6AXlh0WD91CaE7D%2FymW129p%2Fx5xMJc8NWvaRBGmQSQLIsle0hdipXQKeOKXN3RBbVLv143p7wOLcabVOhYK22AMBucZl0dCYo7Nz1%2Bv2UH8AlaiMIkwwa6JPnZW8CQayhJrrEXU91phsb%2Bam8zNr9CIvSfTxgUaI%2BOXryyt%2BEsmyBMm2CMBUUD52Q95HBrw0rSgRQSxFurjKQtgckxQqVyshwDnK%2F884URbCKU9WouvTjpEnHdc%3D
使用上面分析的数据，对于请求进行解密， 并且模拟请求：
```python
def new_video_get_detail_test(video_id):
    request_key = base64.decodebytes(bytes('euZN1Gg3JIwWOEWhmE7C4l5dSSRU34fyuPMXjtuoqVs=', encoding='utf8'))
    request_iv = b'\x49\x09\x3E\x49\x6D\x29\x50\xBB\xF1\x67\x9C\x5D\x52\x77\xBF\x4E'
    request_iv = base64.decodebytes(bytes('HTpKwS4MVfB2pktFSGRzvw==', encoding='utf8'))

    # {"an_stream":"https://tv-as.00ph.cn","timestamp":"1593568332","an_quality":"240","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/video/info/65696"}
    ss = '{"an_stream":"https://tv-as.00ph.cn","timestamp":"' + str(int(
        time.time())) + '","an_quality":"240","token":"eyJ1c2VyX2lkIjoyMTg4MjU2NCwibGFzdGxvZ2luIjoxNTkzMzI3NzQyfQ.c39375da9af6cf24aae0349c4f0b5641.9b0e72bc9a1eea26114dc955d730603e4c11f865d43ea9595d9fd29c","path":"v1/video/info/' + video_id + '"}'

    ds = AES_Encrypt_raw(request_key, ss, request_iv)
    print(ds)
    payload = 'HTpKwS4MVfB2pktFSGRzvw==.' + ds
    base_url = 'https://api.bdxxo.cn/v1/video/info/' + video_id + '?payload=' + urllib.parse.quote(payload)

    print(base_url)
    resp = requests.get(base_url)
    print(resp.text)

    # 1216557403 x-vtag
    response_headers = resp.headers
    vtag = response_headers.get('x-vtag')
    print(vtag)

    i = md5(vtag)
    print(i)
    iv = i[8:24]
    print(iv)
    new_key = md5('fe34dd6bbd3020c2fb69abe73b5b973c')
    dds = AES_Decrypt(new_key.encode('utf8'),
                      resp.text,
                      iv.encode('utf8'))
    print(dds)
```
返回数据信息：
```json
{
    "status":{
        "code":200,
        "message":"success"
    },
    "response":{
        "video_id":"64852",
        "video_title":"秀人网嫩模龙泽美曦宾馆与土豪援交！被玩到尖叫 汁液狂流",
        "actor":[
            "素人"],
        "video_urls":{
            "240":"https:\/\/tv-as.00ph.cn\/media\/240\/64852.m3u8?expire=1593570576&hash=4f11da5357d1b89828a952984fef1177",
            "480":"https:\/\/tv-as.00ph.cn\/media\/240\/64852.m3u8?expire=1593570576&hash=4f11da5357d1b89828a952984fef1177"
        },
        "cover_url":"\/tv_adult\/avid5ba324d210218.jpg?k=166aea03d3630b419d8f23ec3078202a&t=1593569676",
        "cover":"\/tv_adult\/avid5ba324d210218.jpg?k=166aea03d3630b419d8f23ec3078202a&t=1593569676",
        "thumb":"\/tv_adult\/avid5ba324d210218.jpg?k=166aea03d3630b419d8f23ec3078202a&t=1593569676",
        "upload_date":1593351002,
        "release_date":0,
        "video_duration":1260,
        "video_like":false,
        "video_publisher":"",
        "video_number":"avid5ba324d210218",
        "video_category":[
            "小視頻"],
        "video_tags":[
            "小视频",],
        "video_description":"",
        "status":2,
        "open_date":1593351002
    }
}

```
到这里全部的数据接本就都有了，不过还有最后一点需要处理那就是返回的m3u8文件也是加密的，需要进行解密。解密方式与其他请求的解密方式一致。
不仅如此，返回的播放列表的地址也是带有效期参数。
对于播放地址，请求之后进行解密就可以看到m3u8文件的全部内容了：
```text
#EXTM3U
#EXT-X-VERSION:4
#EXT-X-PLAYLIST-TYPE:VOD
#EXT-X-INDEPENDENT-SEGMENTS
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-KEY:METHOD=AES-128,URI="https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/key.php",IV=0xB3DFF72D36D4408E5B4CDF180B9EE03B
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-0.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-1.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-2.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-3.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-4.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-5.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-6.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-7.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-8.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-9.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-10.ts
#EXTINF:6.000000,
https://stream.00ph.cn/tv_adult/avid5ba324d210218/240/ts/avid5ba324d210218-11.ts
```
解密后的m3u8文件就可以扔给ffmpeg下载了：
![ffmepg](screenshots/ffmpeg.jpg)  


总结
-----

1. apk整体的数据加密做的比较全，如果要获取数据需要对全部的数据进行分析拆分。否则无法正常展示相关信息
2. 所有的数据都存在有效期，过了有效期之后将无法访问，于是要爬取这个app的数据需要本地存储部分数据，
    >- 解密后的图片资源
    >- 解密后的m3u8文件
3. 可能还有其他的数据需要解密，这个感兴趣的自己去处理吧。这里就不写了，处理方式可以参考上面的方法。
4. 分析了一些app和网站，这个算是数据加密做的比较彻底的，基本服务器返回的数据全部进行加密了，没有任何明文的内容。安全意识不错。

apk文件下载地址： ZnUyLmxpdmUv