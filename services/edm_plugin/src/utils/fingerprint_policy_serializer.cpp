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

#include "fingerprint_policy_serializer.h"

#include "cJSON.h"

namespace OHOS {
namespace EDM {
const std::string TRUE_VALUE = "true";
bool FingerprintPolicySerializer::Deserialize(const std::string &data, FingerprintPolicy &result)
{
    cJSON* root = cJSON_Parse(data.c_str());
    if (root == nullptr) {
        return true;
    }
    if (cJSON_IsBool(root)) {
        result.globalDisallow = cJSON_IsTrue(root);
        cJSON_Delete(root);
        return true;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        if (!cJSON_IsNumber(item)) {
            continue;
        }
        result.accountIds.insert(item->valueint);
    }
    cJSON_Delete(root);
    return true;
}

bool FingerprintPolicySerializer::Serialize(const FingerprintPolicy &result, std::string &data)
{
    if (result.globalDisallow) {
        data = TRUE_VALUE;
        return true;
    }
    if (result.accountIds.empty()) {
        return true;
    }
    cJSON* root = cJSON_CreateArray();
    for (auto& it : result.accountIds) {
        cJSON* item = cJSON_CreateNumber(it);
        cJSON_AddItemToArray(root, item);
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr != nullptr) {
        data = std::string(jsonStr);
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
    return true;
}

bool FingerprintPolicySerializer::GetPolicy(MessageParcel &data, FingerprintPolicy &result)
{
    return true;
}

bool FingerprintPolicySerializer::WritePolicy(MessageParcel &reply, FingerprintPolicy &result)
{
    return true;
}

bool FingerprintPolicySerializer::MergePolicy(std::vector<FingerprintPolicy> &data, FingerprintPolicy &result)
{
    if (!data.empty()) {
        result = data.back();
    }
    return true;
}
} // namespace EDM
} // namespace OHOS