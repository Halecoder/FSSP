### 声明
#### 技术不精, 纯靠 ChatGPT 提示出来的……所以代码中存在非常多的堆砌痕迹, 部署也非常不方便, 有能力的佬可以仅借鉴部分代码或者思路。  
#### 本项目仅用于分享符合相关法律法规的订阅链接，本人不为订阅链接的作用与内容负责。  

### 说明
后端是 `app.py`, 配置在 `config.py` 中填写, 相关作用可以查看注释或者询问 ChatGPT。  


订阅代理使用的代理服务器在 `app.py` 的 `847` 行更改。  
注意！请设置代理域名黑名单或设置代理服务器或使用高防服务器, 防止服务器 IP 泄露所带来的风险。  
目前的订阅代理功能还不完善, 可能无法正常导入订阅。  
代理功能更强大的后端我提供为 `pp.py` 了, 经过测试似乎是可以正常代理大部分订阅的, 需要整合进 `app.py`, 交给你了。  


订阅代理的逻辑是：
1. 用 AES 算法加密订阅的 `ID`, 获得 `加密后的订阅 ID`;
2. 访问 `/getsub/<encrypted_id>` 路由时, 解密 `加密后的订阅 ID`, 得到 `订阅 ID`;
3. 使用 `订阅 ID` 查询数据库, 获得 `订阅 URL` 并交给后端代理。


可以设置特权用户。在 `app.py` 中搜索 `29403` 即可更改。`29403` 是从 OAuth 应用获取的 `id` 参数。
1. 一种特权用户允许在较低等级绕过等级限制直接访问 FSSP;
2. 一种特权用户可以在管理面板中删除任何人的订阅。

可以封禁用户, 在 `user_info` 数据表中将用户的 `status` 设置为 `banned` 即可。你可提前插入仅包含 `id` 和 `banned` 状态来提前封禁用户。  


代码中头像获取有问题。头像可通过 OAuth 的 `avatar_url` 参数来获取。  


你可以用 1Panel 创建一个数据库, 然后再导入同文件夹下的数据库备份文件 `DBbackup.sql.gz`。让后端连接到导入后的数据库最方便。你也可以创建新数据库。  


`requirements.txt` 大概是完整的，若不完整, 可以缺啥补啥。  


使用 `9527` 端口, 你可以自己修改。  


### 部署
#### 创建数据库并导入我提供的数据库文件

#### 接入 OAuth
https://wiki.linux.do/services/community/Linux-Do-Connect

#### 修改 `config.py`

#### 安装所需库并启动
```
pip install -r requirements.txt
python3 app.py
```
