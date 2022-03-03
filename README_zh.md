# 企业设备管理组件介绍

## 简介

**企业设备管理组件**为企业环境下的应用提供系统级别的管理功能API。

企业设备管理组件架构如下图所示：

![](figure\enterprise_device_management.png)

## 目录

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

## 说明

设备管理组件提供了企业设备管理应用开发模板，支持设备管理应用激活、安全策略设置、系统配置和管理。

## 相关仓

[admin_provisioning](https://gitee.com/openharmony/applications_admin_provisioning)

[appexecfwk_standard](https://gitee.com/openharmony/appexecfwk_standard)

