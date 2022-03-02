# 企业设备管理组件介绍<a name="ZH-CN_TOPIC_0000001232012425"></a>

-   [简介](#section11333318500)
-   [目录](#section145135295018)
-   [说明](#section1413462511513)
-   [相关仓](#section898171518525)

## 简介<a name="section11333318500"></a>

**企业设备管理组件**为企业环境下的应用提供系统级别的管理功能API。

## 目录<a name="section145135295018"></a>

企业设备管理组件源代码目录结构如下所示：

````
/base/customization/enterprise_device_management
├── common                   # 公共代码
├── etc                      # 组件包含的进程的配置文件
├── interfaces               # 组件对外提供的接口代码
│   └── innerkits            # 服务间接口
├── profile                  # 组件包含的系统服务的配置文件
└── services                 # 企业设备管理服务实现
```
````

## 说明<a name="section1413462511513"></a>

设备管理组件提供了企业设备管理应用开发模板，支持设备管理应用激活，安全策略设置，系统配置和管理。

## 相关仓<a name="section898171518525"></a>

[全球化子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%85%A8%E7%90%83%E5%8C%96%E5%AD%90%E7%B3%BB%E7%BB%9F.md)