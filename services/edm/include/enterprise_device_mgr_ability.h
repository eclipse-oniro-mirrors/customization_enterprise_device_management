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

#ifndef SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H_
#define SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H_

#include <bundle_mgr_interface.h>
#include <string>
#include "admin_manager.h"
#include "enterprise_device_mgr_stub.h"
#include "hilog/log.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "system_ability.h"

namespace OHOS {
namespace EDM {
class EnterpriseDeviceMgrAbility : public SystemAbility, public EnterpriseDeviceMgrStub {
    DECLARE_SYSTEM_ABILITY(EnterpriseDeviceMgrAbility);

public:
    EnterpriseDeviceMgrAbility();
    DISALLOW_COPY_AND_MOVE(EnterpriseDeviceMgrAbility);
    ~EnterpriseDeviceMgrAbility();
    static sptr<EnterpriseDeviceMgrAbility> GetInstance();

    ErrCode ActiveAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type,
        int32_t userId) override;
    ErrCode DeactiveAdmin(AppExecFwk::ElementName &admin, int32_t userId) override;
    ErrCode DeactiveSuperAdmin(std::string &bundleName) override;
    ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data) override;
    ErrCode GetDevicePolicy(uint32_t code, AppExecFwk::ElementName *admin, MessageParcel &reply) override;
    ErrCode GetActiveAdmin(AdminType type, std::vector<std::string> &activeAdminList) override;
    ErrCode GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply) override;
    ErrCode SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo) override;
    bool IsSuperAdmin(std::string &bundleName) override;
    bool IsAdminActive(AppExecFwk::ElementName &admin) override;

protected:
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;

private:
    bool IsHdc();
    ErrCode CheckPermission();
    ErrCode CheckCallingUid(std::string &bundleName);
    ErrCode RemoveAdminItem(std::string adminName, std::string policyName, std::string policyValue);
    ErrCode RemoveAdmin(const std::string &adminName);
    ErrCode GetAllPermissionsByAdmin(const std::string& bundleInfoName,
        std::vector<std::string> &permissionList, int32_t userId);
    ErrCode UpdateDeviceAdmin(AppExecFwk::ElementName &admin);
    ErrCode VerifyActiveAdminCondition(AppExecFwk::ElementName &admin, AdminType type);
    bool VerifyCallingPermission(const std::string &permissionName);
    sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr();
    static std::mutex mutexLock_;
    static sptr<EnterpriseDeviceMgrAbility> instance_;
    std::shared_ptr<PolicyManager> policyMgr_;
    std::shared_ptr<AdminManager> adminMgr_;
    std::shared_ptr<PluginManager> pluginMgr_;
    bool registerToService_ = false;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_INCLUDE_EDM_ENTERPRISE_DEVICE_MGR_ABILITY_H_
