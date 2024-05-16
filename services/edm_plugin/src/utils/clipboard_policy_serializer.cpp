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

#include "clipboard_policy_serializer.h"

#include "cJSON.h"

namespace OHOS {
namespace EDM {

bool ClipboardSerializer::Deserialize(const std::string &data, std::map<int32_t, ClipboardPolicy> &result)
{
    cJSON* root = cJSON_Parse(data.c_str());
    if (root == nullptr) {
        return true;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* tokenId = cJSON_GetObjectItem(item, TOKEN_ID.c_str());
        cJSON* clipboardPolicy = cJSON_GetObjectItem(item, CLIPBOARD_POLICY_STR.c_str());
        if (tokenId == nullptr || clipboardPolicy == nullptr) {
            cJSON_Delete(root);
            return false;
        }
        if (!cJSON_IsNumber(clipboardPolicy) || !cJSON_IsNumber(tokenId)) {
            continue;
        }
        auto policyEnum = ConvertToClipboardPolicy(clipboardPolicy->valueint);
        result.insert(std::make_pair(tokenId->valueint, policyEnum));
    }
    cJSON_Delete(root);
    return true;
}

bool ClipboardSerializer::Serialize(const std::map<int32_t, ClipboardPolicy> &result, std::string &data)
{
    if (result.empty()) {
        return true;
    }
    cJSON* root = cJSON_CreateArray();
    for (auto& it : result) {
        cJSON* item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, TOKEN_ID.c_str(), it.first);
        cJSON_AddNumberToObject(item, CLIPBOARD_POLICY_STR.c_str(), static_cast<int32_t>(it.second));
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

bool ClipboardSerializer::GetPolicy(MessageParcel &data, std::map<int32_t, ClipboardPolicy> &result)
{
    int32_t tokenId = data.ReadInt32();
    int32_t policy = data.ReadInt32();
    result.insert(std::make_pair(tokenId, ConvertToClipboardPolicy(policy)));
    return true;
}

bool ClipboardSerializer::WritePolicy(MessageParcel &reply, std::map<int32_t, ClipboardPolicy> &result)
{
    return true;
}

bool ClipboardSerializer::MergePolicy(std::vector<std::map<int32_t, ClipboardPolicy>> &data,
    std::map<int32_t, ClipboardPolicy> &result)
{
    if (!data.empty()) {
        result = data.back();
    }
    return true;
}

ClipboardPolicy ClipboardSerializer::ConvertToClipboardPolicy(int32_t policy)
{
    switch (policy) {
        case static_cast<int32_t>(ClipboardPolicy::IN_APP):
            return ClipboardPolicy::IN_APP;
        case static_cast<int32_t>(ClipboardPolicy::LOCAL_DEVICE):
            return ClipboardPolicy::LOCAL_DEVICE;
        case static_cast<int32_t>(ClipboardPolicy::CROSS_DEVICE):
            return ClipboardPolicy::CROSS_DEVICE;
        default:
            return ClipboardPolicy::DEFAULT;
    }
}
} // namespace EDM
} // namespace OHOS