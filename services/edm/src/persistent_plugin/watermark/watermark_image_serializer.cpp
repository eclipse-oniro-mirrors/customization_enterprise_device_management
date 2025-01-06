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

#include "watermark_image_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const BUNDLE_NAME = "bundleName";
const char* const ACCOUNT_ID = "accountId";
const char* const FILE_NAME = "fileName";
const char* const WIDTH = "width";
const char* const HEIGHT = "height";

bool WatermarkImageSerializer::Deserialize(const std::string &policy,
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(policy.c_str());
    if (root == nullptr) {
        return false;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* bundleName = cJSON_GetObjectItem(item, BUNDLE_NAME);
        cJSON* accountId = cJSON_GetObjectItem(item, ACCOUNT_ID);
        cJSON* fileName = cJSON_GetObjectItem(item, FILE_NAME);
        cJSON* width = cJSON_GetObjectItem(item, WIDTH);
        cJSON* height = cJSON_GetObjectItem(item, HEIGHT);
        if (bundleName == nullptr || accountId == nullptr || fileName == nullptr ||
            width == nullptr || height == nullptr || !cJSON_IsString(bundleName)
            || !cJSON_IsString(fileName) || !cJSON_IsNumber(width) ||
            !cJSON_IsNumber(accountId) || !cJSON_IsNumber(height)) {
            cJSON_Delete(root);
            return false;
        }
        std::pair<std::string, int32_t> key{cJSON_GetStringValue(bundleName), accountId->valueint};
        std::string fileNameStr = cJSON_GetStringValue(fileName);
        WatermarkImageType imageType{fileNameStr, width->valueint, height->valueint};
        dataObj.insert(std::make_pair(key, imageType));
    }
    cJSON_Delete(root);
    return true;
}

bool WatermarkImageSerializer::Serialize(const std::map<std::pair<std::string, int32_t>, WatermarkImageType> &dataObj,
    std::string &policy)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (auto& it : dataObj) {
        cJSON* item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);
        cJSON_AddStringToObject(item, BUNDLE_NAME, it.first.first.c_str());
        cJSON_AddNumberToObject(item, ACCOUNT_ID, it.first.second);
        cJSON_AddStringToObject(item, FILE_NAME, it.second.fileName.c_str());
        cJSON_AddNumberToObject(item, WIDTH, it.second.width);
        cJSON_AddNumberToObject(item, HEIGHT, it.second.height);
        cJSON_AddItemToArray(root, item);
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    policy = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool WatermarkImageSerializer::GetPolicy(MessageParcel &data,
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result)
{
    return true;
}

bool WatermarkImageSerializer::WritePolicy(MessageParcel &reply,
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result)
{
    return true;
}

bool WatermarkImageSerializer::MergePolicy(
    std::vector<std::map<std::pair<std::string, int32_t>, WatermarkImageType>> &data,
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> &result)
{
    if (!data.empty()) {
        result = data.back();
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
