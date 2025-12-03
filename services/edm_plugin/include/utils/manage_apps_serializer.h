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

#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGE_APPS_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGE_APPS_SERIALIZER_H

#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "application_instance.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of type std::vector<ApplicationInstance>.
 */
class ManageAppsSerializer : public IPolicySerializer<std::vector<ApplicationInstance>>,
    public DelayedSingleton<ManageAppsSerializer> {
public:
    std::vector<ApplicationInstance> SetUnionPolicyData(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &currentData);

    std::vector<ApplicationInstance> SetDifferencePolicyData(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &currentData);

    std::vector<ApplicationInstance> SetIntersectionPolicyData(std::vector<ApplicationInstance> &data,
        std::vector<ApplicationInstance> &currentData);

    std::vector<ApplicationInstance> SetNeedRemoveMergePolicyData(std::vector<ApplicationInstance> &mergeData,
        std::vector<ApplicationInstance> &data);

    std::string MakeKey(const ApplicationInstance &item);

    bool Deserialize(const std::string &policy, std::vector<ApplicationInstance> &dataObj) override;

    bool Serialize(const std::vector<ApplicationInstance> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::vector<ApplicationInstance> &result) override;

    bool WritePolicy(MessageParcel &reply, std::vector<ApplicationInstance> &result) override;

    bool MergePolicy(std::vector<std::vector<ApplicationInstance>> &data,
        std::vector<ApplicationInstance> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif //SERVICES_EDM_INCLUDE_UTILS_MANAGE_APPS_SERIALIZER_H