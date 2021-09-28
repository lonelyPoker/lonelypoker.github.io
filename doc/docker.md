## docker 镜像加速
```bash 
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": ["https://v9ocj7eu.mirror.aliyuncs.com"]
}
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
```


## docker环境下安装rabbitmq

```bash 
docker pull rabbitmq:management

docker run -dit --name rabbit --restart always -e RABBITMQ_DEFAULT_USER=guest -e RABBITMQ_DEFAULT_PASS=guest \
 -v /mnt/docker/rabbit/data:/var/lib/rabbitmq  -p 15672:15672 -p 5672:5672 rabbitmq:management
```

## docker环境下安装挂载redis

```bash 
sudo docker run -d --privileged=true -p 6379:6379 --restart always -v \
 /mnt/docker/redis/conf/redis.conf:/etc/redis/redis.conf -v /mnt/docker/redis/data:/data \
  --name redis redis redis-server /etc/redis/redis.conf --appendonly yes
```

## docker 环境下安装挂载mongo
```bash 
sudo docker run -itd --name mongodb --restart=always --privileged=true -p 27017:27017 -v /mnt/docker/mongo/data:/data/db mongo:latest 
```
## docker 环境下安装挂载nginx
```bash
docker run --name nginx -p 8000:80 --restart always -v /data/nginx/conf/nginx.conf:/etc/nginx/nginx.conf \
-v /data/nginx/conf.d/default.conf:/etc/nginx/conf.d/default.conf -itd nginx
```
## docker环境下部署webdav服务
```bash
docker run -d --name=webdav-aliyundriver --restart=always -p 8080:8080  \
-v /etc/localtime:/etc/localtime -v /etc/aliyun-driver/:/etc/aliyun-driver/ \
-e TZ="Asia/Shanghai" -e ALIYUNDRIVE_REFRESH_TOKEN=fe8ae0f8e23545e6840ec10763a891d0 \
-e ALIYUNDRIVE_AUTH_PASSWORD="admin" -e JAVA_OPTS="-Xmx1g" zx5253/webdav-aliyundriver

# /etc/aliyun-driver/ 挂载卷自动维护了最新的refreshToken，建议挂载
# ALIYUNDRIVE_AUTH_PASSWORD 是admin账户的密码，建议修改
# JAVA_OPTS 可修改最大内存占用，比如 -e JAVA_OPTS="-Xmx512m" 表示最大内存限制为512m
```

## docker login 认证问题
```bash 
# x509: certificate signed by unknown authority
wget --ftp-user=admin --ftp-password=admin123@QGS -r -nH -l0 ftp://192.168.2.210/certs.d -P /etc/docker

# 重启docker
systemctl restart docker 
```


## linux环境下rclone挂载onedriver网盘
```bash 
rclone mount centos:/dev/ /home/onedriver/ --file-perms 777 --cache-dir /home/file_cache/ \
--copy-links --no-gzip-encoding --no-check-certificate --allow-other --allow-non-empty --vfs-cache-mode writes
```


