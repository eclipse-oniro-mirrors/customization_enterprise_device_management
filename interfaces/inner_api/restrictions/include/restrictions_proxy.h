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

#ifndef INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H
#define INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H
#include "enterprise_device_mgr_proxy.h"

#include "edm_constants.h"

namespace OHOS {
namespace EDM {
class RestrictionsProxy {
public:
    static std::shared_ptr<RestrictionsProxy> GetRestrictionsProxy();
    int32_t SetDisallowedPolicy(const AppExecFwk::ElementName &admin, bool disallow, int policyCode,
        std::string permissionTag = EdmConstants::PERMISSION_TAG_VERSION_11);
    int32_t GetDisallowedPolicy(AppExecFwk::ElementName *admin, int policyCode, bool &result,
        std::string permissionTag = EdmConstants::PERMISSION_TAG_VERSION_11);
    int32_t SetFingerprintAuthDisabled(const AppExecFwk::ElementName &admin, bool disallow);
    int32_t IsFingerprintAuthDisabled(AppExecFwk::ElementName *admin, bool &result);
    int32_t SetDisallowedPolicyForAccount(const AppExecFwk::ElementName &admin, bool disallow, uint32_t policyCode,
        std::string permissionTag, int32_t accountId);
    int32_t GetDisallowedPolicyForAccount(AppExecFwk::ElementName &admin, int policyCode, bool &result,
        std::string permissionTag, int32_t accountId);

    int32_t AddOrRemoveDisallowedListForAccount(const AppExecFwk::ElementName &admin, std::string feature,
        std::vector<std::string> &bundles, int32_t accountId, bool isAdd);
    int32_t GetDisallowedListForAccount(AppExecFwk::ElementName &admin, std::string feature, int32_t accountId,
        std::vector<std::string> &result);
private:
    static std::shared_ptr<RestrictionsProxy> instance_;
    static std::mutex mutexLock_;
    bool GetDisallowedListInterfaceCode(std::string feature, std::uint32_t &ipcCode);
    std::unordered_map<std::string, std::uint32_t> featureInterfaceMap_ = {
        {"snapshot_skip", EdmInterfaceCode::SNAPSHOT_SKIP}
    };
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_RESTRICTIONS_INCLUDE_RESTRICTIONS_PROXY_H