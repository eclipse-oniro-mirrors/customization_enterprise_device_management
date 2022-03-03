# 企业设备管理组件介绍<a name="ZH-CN_TOPIC_0000001232012425"></a>

-   [简介](#section11333318500)
-   [目录](#section145135295018)
-   [说明](#section1413462511513)
-   [相关仓](#section898171518525)

## 简介<a name="section11333318500"></a>

**企业设备管理组件**为企业环境下的应用提供系统级别的管理功能API。

企业设备管理组件架构如下图所示：

![](figure\EnterpriseDeviceManagement.PNG)

## 目录<a name="section145135295018"></a>

企业设备管理组件源代码目录结构如下所示：

````
/base/customization/enterprise_device_management
├── common                   # 公共代码
├── etc                      # 组件包含的进程的配置文件
├── interfaces               # EdmKits代码
│   └── innerkits            # 子系统接口
│   └── kits                 # 开发者接口
├── profile                  # 组件包含的系统服务的配置文件
└── services                 # 企业设备管理服务实现
```
````

## 说明<a name="section1413462511513"></a>

设备管理组件提供了企业设备管理应用开发模板，支持设备管理应用激活、安全策略设置、系统配置和管理。

## 相关仓<a name="section898171518525"></a>

[admin_provisioning](https://gitee.com/openharmony/applications_admin_provisioning)

[appexecfwk_standard](https://gitee.com/openharmony/appexecfwk_standard)

