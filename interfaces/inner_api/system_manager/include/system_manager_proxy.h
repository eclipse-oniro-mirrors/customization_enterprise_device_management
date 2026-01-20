/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_PROXY_H
#define INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_PROXY_H

#include "enterprise_device_mgr_proxy.h"

#include "func_code.h"
#include "update_policy_utils.h"
#include "key_code.h"

namespace OHOS {
namespace EDM {
class SystemManagerProxy {
public:
    static std::shared_ptr<SystemManagerProxy> GetSystemManagerProxy();
    int32_t SetNTPServer(MessageParcel &data);
    int32_t GetNTPServer(MessageParcel &data, std::string &value);
    int32_t SetOTAUpdatePolicy(MessageParcel &data, std::string &errorMsg);
    int32_t GetOTAUpdatePolicy(MessageParcel &data, UpdatePolicy &updatePolicy);
    int32_t NotifyUpdatePackages(const AppExecFwk::ElementName &admin, UpgradePackageInfo &packageInfo,
        std::string &errMsg);
    int32_t GetUpgradeResult(const AppExecFwk::ElementName &admin, const std::string &version,
        UpgradeResult &upgradeResult);
    int32_t GetUpdateAuthData(MessageParcel &data, std::string &authData);
    int32_t SetAutoUnlockAfterReboot(MessageParcel &data);
    int32_t GetAutoUnlockAfterReboot(MessageParcel &data, bool &authData);
    int32_t SetInstallLocalEnterpriseAppEnabled(MessageParcel &data);
    int32_t GetInstallLocalEnterpriseAppEnabled(MessageParcel &data, bool &isAllowedInstall);
    int32_t AddOrRemoveDisallowedNearlinkProtocols(MessageParcel &data, FuncOperateType operateType);
    int32_t GetDisallowedNearlinkProtocols(MessageParcel &data, std::vector<int32_t> &protocols);
    int32_t SetKeyEventPolicys(const AppExecFwk::ElementName &admin,
        const std::vector<KeyCustomization> &KeyCustomizations, std::string &retMessage);
    int32_t RemoveKeyEventPolicys(const AppExecFwk::ElementName &admin, const std::vector<int32_t> &KeyCodes);
    int32_t GetKeyEventPolicys(const AppExecFwk::ElementName &admin,
        std::vector<KeyCustomization> &KeyCustomizations);
    int32_t SetActivationLockDisabled(const AppExecFwk::ElementName &admin, bool &isDisabled,
        std::string &credential);
    int32_t IsActivationLockDisabled(AppExecFwk::ElementName &admin, bool &result);

#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
    int32_t StartCollectlog(const AppExecFwk::ElementName &admin);
    int32_t FinishLogCollected(MessageParcel &data);
#endif
private:
    static std::shared_ptr<SystemManagerProxy> instance_;
    static std::once_flag flag_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_SYSTEM_MANAGER_PROXY_H
