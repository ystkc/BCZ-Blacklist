
用途：将用户分为不同的权限组，通过管理员修改或预先配置权限组。

所有权限组用户都可以搜索查看所有记录，但只能修改或删除自己创建的记录，且只能添加信息到不大于自己权限组的表单。

本程序设置了1个游客权限组，3个普通权限组和1个管理员权限组，同时可以通过`USER_TYPE_STR_MAP`常量设置快速添加或修改权限组。

用户和qq号一一对应。

本程序带有内存操作日志，但暂无自动回撤功能，请定期访问`http://localhost:8870/oapi/download`（需要登录管理员账号）备份数据库。

配置方法：

1. 安装python 3.11.0，并按照requirement.txt安装依赖包。

2. 运行app.py文件，然后访问`http://localhost:8870/`

3. 按照页面提示，注册一个管理员账号并登录。

4. 访问`http://localhost:8870/config`，配置好用于发送验证码的邮箱和短信平台的授权信息。

5. 访问`http://localhost:8870/submit`，按照如下格式批量添加权限组2的用户名单（权限组0为游客，权限组1为默认注册的普通用户）

```
qq号1,用户名1,
qq号2,用户名2,
...
```

这些用户将会在注册添加密码后自动加入权限组2。
