/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#ifndef COMMON_NATIVE_INSTALL_LOCAL_ENTERPRISE_APP_POLICY_UTILS_H
#define COMMON_NATIVE_INSTALL_LOCAL_ENTERPRISE_APP_POLICY_UTILS_H
 
#include <optional>
#include <string>
 
#include "edm_errors.h"
 
namespace OHOS {
namespace EDM {
class InstallLocalEnterpriseAppPolicyUtils {
public:
    static ErrCode UpdatePolicyByUser(std::optional<int32_t> userId = std::nullopt);
    static ErrCode UpdateSettingsPolicy(int32_t policyValue, std::optional<int32_t> userId = std::nullopt);
    static ErrCode SetEnterpriseUserPolicy(bool data, int32_t userId);
    static ErrCode SetSettingsDataAndUserPolicy(int32_t policyValue, std::optional<int32_t> userId = std::nullopt);
 
    static constexpr int32_t POLICY_NO_CONTROLL = 0;
    static constexpr int32_t POLICY_FORCE_ENABLE = 1;
    static constexpr int32_t POLICY_FORCE_DISABLE = 2;
private:
    static constexpr const char *CONSTRAINT_LOCAL_INSTALL =
        "constraint.enterprise.bundles.local.install.disallow";
    static constexpr const char *PERSIST_LOCAL_INSTALL_ENABLE = "persist.edm.is_local_install_enable";
 
    static int32_t GetPolicyValueFromRdb(const std::string &policyValue);
    static ErrCode WriteDeviceSettingsData(int32_t policyValue);
    static ErrCode WriteUserSettingsData(int32_t policyValue, int32_t userId);
    static bool GetDeviceActualPolicyValue();
    static bool GetUserActualPolicyValue(int32_t userId);
    static ErrCode UpdateOsAccountConstraint(bool value, int32_t userId);
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INSTALL_LOCAL_ENTERPRISE_APP_POLICY_UTILS_H