/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H
#define FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H

#include <iremote_broker.h>
#include <string_ex.h>

#include "policy_struct.h"
#include "policy_changed_event.h"

namespace OHOS {
namespace EDM {

/**
 * @brief 企业管理员IPC接口，定义了EDM系统与企业管理应用之间的通信协议。
 * 
 * 该接口通过IRemoteBroker实现跨进程通信，企业管理应用需实现此接口以接收
 * EDM系统的各类事件通知，包括管理员启用/禁用、应用安装/卸载、账号变更等。
 */
class IEnterpriseAdmin : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.EDM.IEnterpriseAdmin");

    /**
     * @brief 处理管理员启用/禁用事件。
     * @param code 事件码，取值为COMMAND_ON_ADMIN_ENABLED或COMMAND_ON_ADMIN_DISABLED。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnAdmin(uint32_t code) = 0;

    /**
     * @brief 处理应用包安装/卸载/更新事件。
     * @param code 事件码，取值为COMMAND_ON_BUNDLE_ADDED、COMMAND_ON_BUNDLE_REMOVED或COMMAND_ON_BUNDLE_UPDATED。
     * @param bundleName 应用包名。
     * @param accountId 账户ID。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnBundle(uint32_t code, const std::string &bundleName, int32_t accountId) = 0;

    /**
     * @brief 处理应用启动/停止事件。
     * @param code 事件码，取值为COMMAND_ON_APP_START或COMMAND_ON_APP_STOP。
     * @param bundleName 应用包名。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnApp(uint32_t code, const std::string &bundleName) = 0;

    /**
     * @brief 处理系统更新事件。
     * @param updateInfo 系统更新信息，包含版本号、接收时间、包类型等。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnSystemUpdate(const UpdateInfo &updateInfo) = 0;

    /**
     * @brief 处理账号添加/切换/移除事件。
     * @param code 事件码，取值为COMMAND_ON_ACCOUNT_ADDED、COMMAND_ON_ACCOUNT_SWITCHED或COMMAND_ON_ACCOUNT_REMOVED。
     * @param accountId 账号ID。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnAccount(uint32_t code, const int32_t accountId) = 0;

    /**
     * @brief 处理Kiosk模式进入/退出事件。
     * @param code 事件码，取值为COMMAND_ON_KIOSK_MODE_ENTERING或COMMAND_ON_KIOSK_MODE_EXITING。
     * @param bundleName 当前运行的应用包名。
     * @param accountId 账户ID。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnKioskMode(uint32_t code, const std::string &bundleName, int32_t accountId) = 0;

    /**
     * @brief 处理市场应用安装状态变更事件。
     * @param bundleName 应用包名。
     * @param status 安装状态。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnMarketAppsInstallStatusChanged(const std::string &bundleName, int32_t status) = 0;

    /**
     * @brief 处理设备管理员启用/禁用事件。
     * @param code 事件码，取值为COMMAND_ON_DEVICE_ADMIN_ENABLED或COMMAND_ON_DEVICE_ADMIN_DISABLED。
     * @param bundleName 设备管理员应用包名。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnDeviceAdmin(uint32_t code, const std::string &bundleName) = 0;

    /**
     * @brief 处理日志收集完成事件。
     * @param isSuccess 日志收集是否成功。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnLogCollected(bool isSuccess) = 0;

    /**
     * @brief 处理按键事件。
     * @param event 按键事件信息，JSON格式字符串。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnKeyEvent(const std::string &event) = 0;

    /**
     * @brief 处理开机引导完成事件。
     * @param type 事件类型。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnStartupGuideCompleted(int32_t type) = 0;

    /**
     * @brief 处理设备启动完成事件。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnDeviceBootCompleted() = 0;

    /**
     * @brief 处理管理员策略变更事件。
     * @param policyChangedEvent 策略变更事件，包含策略名称、管理员包名、策略内容等。
     * @return 处理成功返回true，失败返回false。
     */
    virtual bool OnAdminPolicyChanged(const PolicyChangedEvent &policyChangedEvent) = 0;

    /**
     * @brief IPC命令码枚举，定义了所有事件通知的命令码。
     */
    enum {
        /** 管理员启用事件 */
        COMMAND_ON_ADMIN_ENABLED = 1,
        /** 管理员禁用事件 */
        COMMAND_ON_ADMIN_DISABLED = 2,
        /** 应用包安装事件 */
        COMMAND_ON_BUNDLE_ADDED = 3,
        /** 应用包卸载事件 */
        COMMAND_ON_BUNDLE_REMOVED = 4,
        /** 应用启动事件 */
        COMMAND_ON_APP_START = 5,
        /** 应用停止事件 */
        COMMAND_ON_APP_STOP = 6,
        /** 系统更新事件 */
        COMMAND_ON_SYSTEM_UPDATE = 7,
        /** 账号添加事件 */
        COMMAND_ON_ACCOUNT_ADDED = 8,
        /** 账号切换事件 */
        COMMAND_ON_ACCOUNT_SWITCHED = 9,
        /** 账号移除事件 */
        COMMAND_ON_ACCOUNT_REMOVED = 10,
        /** Kiosk模式进入事件 */
        COMMAND_ON_KIOSK_MODE_ENTERING = 11,
        /** Kiosk模式退出事件 */
        COMMAND_ON_KIOSK_MODE_EXITING = 12,
        /** 市场应用安装状态变更事件 */
        COMMAND_ON_MARKET_INSTALL_STATUS_CHANGED = 13,
        /** 设备管理员启用事件 */
        COMMAND_ON_DEVICE_ADMIN_ENABLED = 14,
        /** 设备管理员禁用事件 */
        COMMAND_ON_DEVICE_ADMIN_DISABLED = 15,
        /** 日志收集完成事件 */
        COMMAND_ON_LOG_COLLECTED = 16,
        /** 按键事件 */
        COMMAND_ON_KEY_EVENT = 17,
        /** 开机引导完成事件 */
        COMMAND_ON_STARTUP_GUIDE_COMPLETED = 18,
        /** 设备启动完成事件 */
        COMMAND_ON_DEVICE_BOOT_COMPLETED = 19,
        /** 应用包更新事件 */
        COMMAND_ON_BUNDLE_UPDATED = 20,
        /** 管理员策略变更事件 */
        COMMAND_ON_POLICIES_CHANGED = 21
    };
};
} // namespace EDM
} // namespace OHOS
#endif // FRAMEWORK_EXTENSION_INCLUDE_IENTERPRISE_ADMIN_H