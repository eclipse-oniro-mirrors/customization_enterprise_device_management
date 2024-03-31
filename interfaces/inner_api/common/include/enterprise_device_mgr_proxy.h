/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H
#define INTERFACES_INNER_API_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H

#include <message_parcel.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ienterprise_device_mgr.h"

namespace OHOS {
namespace EDM {
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t HAS_ADMIN = 0;
constexpr int32_t WITHOUT_ADMIN = 1;
constexpr int32_t WITHOUT_USERID = 0;
constexpr int32_t HAS_USERID = 1;
constexpr const char *WITHOUT_PERMISSION_TAG = "";

class EnterpriseDeviceMgrProxy {
public:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> GetInstance();
    static void DestroyInstance();

    ErrCode EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type, int32_t userId);
    ErrCode DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId);
    ErrCode DisableSuperAdmin(const std::string &bundleName);
    ErrCode GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList);
    ErrCode GetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo);
    ErrCode SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo);
    ErrCode HandleManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events,
        bool subscribe);
    ErrCode IsSuperAdmin(const std::string &bundleName, bool &result);
    ErrCode IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId, bool &result);
    int32_t HandleDevicePolicy(int32_t policyCode, MessageParcel &data);
    int32_t HandleDevicePolicy(int32_t policyCode, MessageParcel &data, MessageParcel &reply);
    ErrCode AuthorizeAdmin(const AppExecFwk::ElementName &admin, const std::string &bundleName);
    ErrCode GetSuperAdmin(std::string &bundleName, std::string &abilityName);

    void GetEnabledSuperAdmin(std::string &enabledAdmin);
    bool IsSuperAdminExist();
    void GetEnabledAdmins(std::vector<std::string> &enabledAdminList);
    int32_t SetPolicyDisabled(const AppExecFwk::ElementName &admin, bool isDisabled, uint32_t policyCode,
        std::string permissionTag = WITHOUT_PERMISSION_TAG);
    int32_t IsPolicyDisabled(const AppExecFwk::ElementName *admin, int policyCode, bool &result,
        std::string permissionTag = WITHOUT_PERMISSION_TAG);
    bool GetPolicyValue(AppExecFwk::ElementName *admin, int policyCode, std::string &policyData,
        int32_t userId = DEFAULT_USER_ID);
    bool GetPolicyArray(AppExecFwk::ElementName *admin, int policyCode, std::vector<std::string> &policyData,
        int32_t userId = DEFAULT_USER_ID);
    bool GetPolicyMap(AppExecFwk::ElementName *admin, int policyCode, std::map<std::string, std::string> &policyData,
        int32_t userId = DEFAULT_USER_ID);
    bool GetPolicyData(AppExecFwk::ElementName *admin, int policyCode, int32_t userId, MessageParcel &reply);
    bool GetPolicy(int policyCode, MessageParcel &data, MessageParcel &reply);
    bool IsEdmEnabled();

private:
    sptr<IRemoteObject> LoadAndGetEdmService();
    void GetEnabledAdmins(AdminType type, std::vector<std::string> &enabledAdminList);

    static std::shared_ptr<EnterpriseDeviceMgrProxy> instance_;
    static std::mutex mutexLock_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H
