/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H
#define SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H

#include <bundle_mgr_interface.h>
#include <string>
#include "admin_manager.h"
#include "common_event_subscriber.h"
#include "enterprise_device_mgr_stub.h"
#include "hilog/log.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "system_ability.h"
#include "enterprise_admin_proxy.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrAbility : public SystemAbility, public EnterpriseDeviceMgrStub {
    DECLARE_SYSTEM_ABILITY(EnterpriseDeviceMgrAbility);

public:
    using CommonEventCallbackFunc = void (EnterpriseDeviceMgrAbility::*)(const EventFwk::CommonEventData &data);
    EnterpriseDeviceMgrAbility();
    DISALLOW_COPY_AND_MOVE(EnterpriseDeviceMgrAbility);
    ~EnterpriseDeviceMgrAbility();
    static sptr<EnterpriseDeviceMgrAbility> GetInstance();

    ErrCode EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
        int32_t userId) override;
    ErrCode DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId) override;
    ErrCode DisableSuperAdmin(std::string &bundleName) override;
    ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data) override;
    ErrCode GetDevicePolicy(uint32_t code, AppExecFwk::ElementName *admin, MessageParcel &reply) override;
    ErrCode GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList) override;
    ErrCode GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply) override;
    ErrCode SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo) override;
    ErrCode SubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override;
    ErrCode UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override;
    bool IsSuperAdmin(std::string &bundleName) override;
    bool IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId) override;
    std::unordered_map<std::string, CommonEventCallbackFunc> commonEventFuncMap_;

protected:
    void OnStart() override;
    void OnStop() override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    bool IsHdc();
    void AddCommonEventFuncMap();
    ErrCode CheckCallingUid(std::string &bundleName);
    ErrCode RemoveAdminItem(std::string adminName, std::string policyName, std::string policyValue);
    ErrCode RemoveAdmin(const std::string &adminName, int32_t userId);
    ErrCode GetAllPermissionsByAdmin(const std::string& bundleInfoName,
        std::vector<std::string> &permissionList, int32_t userId);
    int32_t GetCurrentUserId();
    ErrCode UpdateDeviceAdmin(AppExecFwk::ElementName &admin);
    ErrCode VerifyEnableAdminCondition(AppExecFwk::ElementName &admin, AdminType type, int32_t userId);
    ErrCode HandleManagedEvent(const AppExecFwk::ElementName &admin,
        const std::vector<uint32_t> &events, bool subscribe);
    bool VerifyCallingPermission(const std::string &permissionName);
    sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr();
    std::shared_ptr<EventFwk::CommonEventSubscriber> CreateEnterpriseDeviceEventSubscriber(
        EnterpriseDeviceMgrAbility &listener);
    void OnCommonEventUserRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageAdded(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageRemoved(const EventFwk::CommonEventData &data);
    void OnCommonEventPackageAddedOrRemoved(const EventFwk::CommonEventData &data, ManagedEvent event);
    bool CheckManagedEvent(uint32_t event);
    static std::mutex mutexLock_;
    static sptr<EnterpriseDeviceMgrAbility> instance_;
    std::shared_ptr<PolicyManager> policyMgr_;
    std::shared_ptr<AdminManager> adminMgr_;
    std::shared_ptr<PluginManager> pluginMgr_;
    bool registerToService_ = false;
    std::shared_ptr<EventFwk::CommonEventSubscriber> commonEventSubscriber = nullptr;
};
class EnterpriseDeviceEventSubscriber : public EventFwk::CommonEventSubscriber {
public:
    EnterpriseDeviceEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        EnterpriseDeviceMgrAbility &listener);
    ~EnterpriseDeviceEventSubscriber() override = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
private:
      EnterpriseDeviceMgrAbility &listener_;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H
