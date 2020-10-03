# socksfilter
socks5过滤器

# 特性
* 监听端口（默认1080），对外提供socks5服务
* 根据目标IP所在国家过滤（默认CN），命中直连，非命中走后端socks5 server
* 后端聚合多个socks5 server，选择方式：遍历（默认）/随机/Hash，同时跳过无效的

# 使用
* 监听本机1080端口，绕过CN地区，非CN地区，转发到后端的socks5 server
```
# ./socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```
* 使用docker
```
# docker run --name socksfilter -d --restart=always --network host esrrhs/socksfilter ./socksfilter -s "yourserver1:1080 yourserver2:1080 yourserver3:1080"
```
