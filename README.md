# socksfilter
socks5过滤器

# 特性
* 根据IP所在国家过滤，命中直连，非命中走后端socks5 server
* 后端聚合多个socks5 server，随机选择或者顺序选择，同时跳过无效的

# 使用
* 监听本机1080端口，绕过CN地区，非CN地区，转发到后端随机的socks5 server
```
# ./socksfilter -l :1080 -s "yourserver1:1080 yourserver2:1080 yourserver3:1080" -skip CN
```
* 使用docker
```
# docker run --name socksfilter -d --restart=always --network host esrrhs/socksfilter ./socksfilter -l :1080 -s "yourserver1:1080 yourserver2:1080 yourserver3:1080" -skip CN
```
* 更多命令参考-h
```
Usage of ./socksfilter:
  -file string
        ip file (default "GeoLite2-Country.mmdb")
  -l string
        listen addr (default ":1080")
  -loglevel string
        log level (default "info")
  -nolog int
        write log file
  -noprint int
        print stdout
  -rand
        select rand server addr (default true)
  -s string
        server addr (default "server1 server2 server3")
  -skip string
        skip country (default "CN")
```
