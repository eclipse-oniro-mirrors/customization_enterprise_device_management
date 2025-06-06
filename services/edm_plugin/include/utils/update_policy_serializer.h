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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_UPDATE_POLICY_SERIALIZER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_UPDATE_POLICY_SERIALIZER_H

#include "singleton.h"

#include "ipolicy_serializer.h"
#include "update_policy_utils.h"

namespace OHOS {
namespace EDM {
/*
* Policy data serializer of type UpdatePolicy.
*/
class UpdatePolicySerializer : public IPolicySerializer<UpdatePolicy>, public DelayedSingleton<UpdatePolicySerializer> {
public:
    bool Deserialize(const std::string &jsonString, UpdatePolicy &dataObj) override;

    bool Serialize(const UpdatePolicy &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, UpdatePolicy &result) override;

    bool WritePolicy(MessageParcel &reply, UpdatePolicy &result) override;

    bool MergePolicy(std::vector<UpdatePolicy> &data, UpdatePolicy &result) override;
};
} // namespace EDM
} // namespace OHOS
#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_UPDATE_POLICY_SERIALIZER_H