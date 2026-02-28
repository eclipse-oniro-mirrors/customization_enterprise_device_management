/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "update_policy_serializer.h"

#include "int_serializer.h"

namespace OHOS {
namespace EDM {
bool UpdatePolicySerializer::Deserialize(const std::string &jsonString, UpdatePolicy &dataObj)
{
    int32_t updatePolicyType = 0;
    IntSerializer::GetInstance()->Deserialize(jsonString, updatePolicyType);
    UpdatePolicyUtils::ProcessUpdatePolicyType(updatePolicyType, dataObj.type);
    return true;
}

bool UpdatePolicySerializer::Serialize(const UpdatePolicy &dataObj, std::string &jsonString)
{
    IntSerializer::GetInstance()->Serialize(static_cast<int32_t>(dataObj.type), jsonString);
    return true;
}

bool UpdatePolicySerializer::GetPolicy(MessageParcel &data, UpdatePolicy &result)
{
    UpdatePolicyUtils::ReadUpdatePolicy(data, result);
    return true;
}

bool UpdatePolicySerializer::WritePolicy(MessageParcel &reply, UpdatePolicy &result)
{
    UpdatePolicyUtils::WriteUpdatePolicy(reply, result);
    return true;
}

bool UpdatePolicySerializer::MergePolicy(std::vector<UpdatePolicy> &data,
    UpdatePolicy &result)
{
    for (auto &policy : data) {
        if (policy.type == UpdatePolicyType::DEFAULT) {
            result.type = policy.type;
        }
    }
    return true;
}
} // namespace EDM
} // namespace OHOS