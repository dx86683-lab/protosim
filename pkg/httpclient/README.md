# httpclient
完成低级别的http请求封装。

## 功能
- http库
    - 支持指定是否跳转
    - 支持自定义header
    - 支持全局代理
    - 在header头包含异常的情况下作为完整字段返回
    - gzip
    - chunked
    - 返回字段
        - utf8编码
        - header
        - statusline
    - 支持请求超时设置
    - 支持指定是否禁止跳转出非本IP:PORT的HOST
    - 支持认证auth字段
    - 当用户的uri指定的是完整路径的时候，直接请求新的url
    - 当响应是非标准HTTP数据时，直接将返回数据赋值RawBoby
    
    
## 未完成
- header只能处理一个，比如多个Set-Cookie情况下会覆盖