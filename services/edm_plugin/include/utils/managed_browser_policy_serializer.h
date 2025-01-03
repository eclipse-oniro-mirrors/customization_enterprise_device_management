/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_INCLUDE_UTILS_MANAGED_BROWSER_POLICY_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_MANAGED_BROWSER_POLICY_SERIALIZER_H

#include "ipolicy_serializer.h"

#include "managed_browser_policy_type.h"

namespace OHOS {
namespace EDM {

/*
 * Policy data serializer of type std::map<std::string, ManagedBrowserPolicyType>.
 */
class ManagedBrowserPolicySerializer : public IPolicySerializer<std::map<std::string, ManagedBrowserPolicyType>>,
    public DelayedSingleton<ManagedBrowserPolicySerializer> {
public:
    bool Deserialize(const std::string &policy, std::map<std::string, ManagedBrowserPolicyType> &dataObj) override;

    bool Serialize(const std::map<std::string, ManagedBrowserPolicyType> &dataObj, std::string &policy) override;

    bool GetPolicy(MessageParcel &data, std::map<std::string, ManagedBrowserPolicyType> &result) override;

    bool WritePolicy(MessageParcel &reply, std::map<std::string, ManagedBrowserPolicyType> &result) override;

    bool MergePolicy(std::vector<std::map<std::string, ManagedBrowserPolicyType>> &data,
        std::map<std::string, ManagedBrowserPolicyType> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_MANAGED_BROWSER_POLICY_SERIALIZER_H