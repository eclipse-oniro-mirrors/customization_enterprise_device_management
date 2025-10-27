/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APPS_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APPS_SERIALIZER_H

#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "manage_freeze_exempted_apps_info.h"
#include "application_instance.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of type std::vector<ManageFreezeExemptedAppInfo>.
 */
class ManageFreezeExemptedAppsSerializer : public IPolicySerializer<std::vector<ManageFreezeExemptedAppInfo>>,
    public DelayedSingleton<ManageFreezeExemptedAppsSerializer> {
public:
    std::vector<ManageFreezeExemptedAppInfo> SetUnionPolicyData(std::vector<ManageFreezeExemptedAppInfo> &data,
        std::vector<ManageFreezeExemptedAppInfo> &currentData);

    std::vector<ManageFreezeExemptedAppInfo> SetDifferencePolicyData(std::vector<ManageFreezeExemptedAppInfo> &data,
        std::vector<ManageFreezeExemptedAppInfo> &currentData);

    std::vector<ManageFreezeExemptedAppInfo> SetIntersectionPolicyData(std::vector<ApplicationMsg> &data,
        std::vector<ManageFreezeExemptedAppInfo> &currentData);

    std::vector<ManageFreezeExemptedAppInfo> SetNeedRemoveMergePolicyData(
        std::vector<ManageFreezeExemptedAppInfo> &mergeData, std::vector<ManageFreezeExemptedAppInfo> &data,
        std::vector<ApplicationMsg> &needRemoveBundles);

    bool Deserialize(const std::string &policy, std::vector<ManageFreezeExemptedAppInfo> &dataObj) override;

    bool Serialize(const std::vector<ManageFreezeExemptedAppInfo> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::vector<ManageFreezeExemptedAppInfo> &result) override;

    bool WritePolicy(MessageParcel &reply, std::vector<ManageFreezeExemptedAppInfo> &result) override;

    bool MergePolicy(std::vector<std::vector<ManageFreezeExemptedAppInfo>> &data,
        std::vector<ManageFreezeExemptedAppInfo> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif //SERVICES_EDM_INCLUDE_UTILS_MANAGE_FREEZE_EXEMPTED_APPS_SERIALIZER_H