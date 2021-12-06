## scrapyd

> Scrapyd 是一个用于部署和运行 Scrapy 蜘蛛的应用程序。它使您能够部署（上传）您的项目并使用 JSON API 控制它们的爬虫。

##### 安装`scrapyd`

`pip install scrapyd`

##### 启动`scrapyd`

`scrapyd`

##### scrapyd基础部署流程 (`EPollReactor`)模式

1. 初始化一个爬虫项目

   `scrapy startproject demo && cd demo && scrapy genspider demospider www.baidu.com `

   ```bash
   ├── demo
   │   ├── __init__.py
   │   ├── items.py
   │   ├── middlewares.py
   │   ├── pipelines.py
   │   ├── __pycache__
   │   │   ├── __init__.cpython-38.pyc
   │   │   └── settings.cpython-38.pyc
   │   ├── settings.py
   │   └── spiders
   │       ├── demospider.py
   │       ├── __init__.py
   │       └── __pycache__
   │           └── __init__.cpython-38.pyc
   └── scrapy.cfg
   ```

2. 配置部署文件`scrapy.cfg`

   ```ini
   # Automatically created by: scrapy startproject
   #
   # For more information about the [deploy] section see:
   # https://scrapyd.readthedocs.io/en/latest/deploy.html
   
   [settings]
   default = demo.settings
   
   #[deploy]
   #url = http://localhost:6800/
   [deploy:demoproject]
   url = http://localhost:6800/
   project = demo
   ```

   部署名:`demoproject`

   项目名:`demo`

   爬虫名称:`demospider`

3. 安装`scrapyd-client`

   `pip install scrapyd-client ` 

4. 上传部署`demo`项目

   `scrapyd-deploy demoproject -p demo ` 

5. 运行调度爬虫

   `curl http://localhost:6800/schedule.json -d project=demo -d spider=demospider`

##### scrapyd进阶部署(`AsyncioSelectorReactor`)

当scrapy项目里面使用 asyncio相关的协程方法以及第三方协程库时，这个时候使用scrapyd基础部署是会出错。

并且scrapy爬虫项目里面不能有安装`AsyncioSelectorReactor`相关的配置及方法 ，要部署时需要将这些安装配置注释掉，否者部署到scrapyd会出错，具体错误不做详细展开讨论。

- 修改`twisted`源码代码安装`AsyncioSelectorReactor`

  - 进入到`twisted`包目录里面 ，不知道如何快速找到包目录可以使用`pip show twisted`

    找到`Location: /root/miniconda3/lib/python3.8/site-packages`

    `vim /root/miniconda3/lib/python3.8/site-packages/twisted/internet/reactor.py ` 

  - 修改`reactor.py`文件

    ```python
    import sys
    
    del sys.modules["twisted.internet.reactor"]
    # from twisted.internet import default
    
    # default.install()
    
    #注释以上两行，接下来安装AsyncioSelectorReactor方法
    from twisted.internet.asyncioreactor import install;install()
    ```

  - 对`scrapy`爬虫及整体`scrapyd`服务的影响

    修改之后本地调用twisted包的模块默认使用`twisted.internet.asyncioreactor.AsyncioSelectorReactor`,不会再使用`twisted.internet.epollreactor.EPollReactor`作为reactor实例，据多方面测试对大部分功能没啥影响，只是效率方面会流失一点。还有一点就是`scrapy`框架`settings.py`无需配置 `install_reactor('twisted.internet.asyncioreactor.AsyncioSelectorReactor')` `TWISTED_REACTOR = 'twisted.internet.asyncioreactor.AsyncioSelectorReactor'`就可以在scrapy框架里面使用相关asyncio协程方法。

- 修改`scrapyd`源码代码安装`AsyncioSelectorReactor`

  - 进入到`scrapyd`包目录里面

    `vim /root/miniconda3/lib/python3.8/site-packages/scrapyd/__init__.py`

  - 修改`__init__.py`文件

    ```python
    import pkgutil
    
    __version__ = pkgutil.get_data(__package__, 'VERSION').decode('ascii').strip()
    version_info = tuple(__version__.split('.')[:3])
    # install asyncioreactor
    from twisted.internet.asyncioreactor import install;install()
    from scrapy.utils.misc import load_object
    from scrapyd.config import Config
    
    
    def get_application(config=None):
        if config is None:
            config = Config()
        apppath = config.get('application', 'scrapyd.app.application')
        appfunc = load_object(apppath)
        return appfunc(config)
    
    ```

  - 对`scrapy`爬虫及整体`scrapyd`服务的影响

    - scrapy本地执行时，若使用了协程方法需要设置`TWISTED_REACTOR = 'twisted.internet.asyncioreactor.AsyncioSelectorReactor'`，上传scrapy项目至`scrapyd`服务之前需要将其`TWISTED_REACTOR `字段注释
    - scrapyd服务启动没有太大改变，依旧`scrapyd`启动服务

- 通过使用`twistd`命令启动`scrapyd`后台服务（无需修改源代码）

  - 进入到`scrapyd`包目录里面，复制`txapp.py`绝对路径
  - 执行命令`twistd -y /root/miniconda3/lib/python3.8/site-packages/scrapyd/txapp.py --reactor=asyncio`
  - 对`scrapy`爬虫及整体`scrapyd`服务的影响
    - scrapy本地执行时，若使用了协程方法需要设置`TWISTED_REACTOR = 'twisted.internet.asyncioreactor.AsyncioSelectorReactor'`，上传scrapy项目至`scrapyd`服务之前需要将其`TWISTED_REACTOR `字段注释







