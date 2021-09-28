## ADB命令操作详情
- **adb forward 端口转发**
    ```bash
    # frida 12.3.6以下版本是需要通过forward转发端口,frida默认端口为27042
    adb forward tcp:27042 tcp:27042
    # adb也是可以转发UDP协议的。例如snmp trap服务是基于UDP来实现的，默认端口为162
    adb forward udp:162 udp:162
    ```
- **adb devices 查看当前可连接移动设备**
    ```bash
    # 存在可用设备
    
    
    # 不存在可用设备时
    # List of devices attached
    ```
    
- **sas**


![](../../asset/img/trickybiddy-005.jpg ":no-zoom")