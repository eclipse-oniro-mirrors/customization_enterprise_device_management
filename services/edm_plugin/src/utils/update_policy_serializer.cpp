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
#include "update_policy_serializer.h"

namespace OHOS {
namespace EDM {
bool UpdatePolicySerializer::Deserialize(const std::string &jsonString, UpdatePolicy &dataObj)
{
    return true;
}

bool UpdatePolicySerializer::Serialize(const UpdatePolicy &dataObj, std::string &jsonString)
{
    return true;
}

bool UpdatePolicySerializer::GetPolicy(MessageParcel &data, UpdatePolicy &result)
{
    UpdatePolicyUtils::ReadUpdatePolicy(data, result);
    return true;
}

bool UpdatePolicySerializer::WritePolicy(MessageParcel &reply, UpdatePolicy &result)
{
    return true;
}

bool UpdatePolicySerializer::MergePolicy(std::vector<UpdatePolicy> &data,
    UpdatePolicy &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS