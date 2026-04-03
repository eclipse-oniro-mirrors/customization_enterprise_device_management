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

#include "screen_watermark_image_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

bool ScreenWatermarkImageSerializer::Deserialize(const std::string &policy, WatermarkImageType &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON *json = cJSON_Parse(policy.c_str());
    if (json == nullptr) {
        EDMLOGE("ScreenWatermarkImageSerializer::Deserialize parse json error");
        return false;
    }
    cJSON *fileNameJson = cJSON_GetObjectItemCaseSensitive(json, "fileName");
    if (fileNameJson == nullptr || !cJSON_IsString(fileNameJson)) {
        EDMLOGE("ScreenWatermarkImageSerializer::Deserialize get fileName error");
        cJSON_Delete(json);
        return false;
    }
    dataObj.fileName = fileNameJson->valuestring;
    cJSON *widthJson = cJSON_GetObjectItemCaseSensitive(json, "width");
    if (widthJson == nullptr || !cJSON_IsNumber(widthJson)) {
        EDMLOGE("ScreenWatermarkImageSerializer::Deserialize get width error");
        cJSON_Delete(json);
        return false;
    }
    dataObj.width = widthJson->valueint;
    cJSON *heightJson = cJSON_GetObjectItemCaseSensitive(json, "height");
    if (heightJson == nullptr || !cJSON_IsNumber(heightJson)) {
        EDMLOGE("ScreenWatermarkImageSerializer::Deserialize get height error");
        cJSON_Delete(json);
        return false;
    }
    dataObj.height = heightJson->valueint;
    cJSON_Delete(json);
    return true;
}

bool ScreenWatermarkImageSerializer::Serialize(const WatermarkImageType &dataObj, std::string &policy)
{
    cJSON *json = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(json, false);
    cJSON_AddStringToObject(json, "fileName", dataObj.fileName.c_str());
    cJSON_AddNumberToObject(json, "width", dataObj.width);
    cJSON_AddNumberToObject(json, "height", dataObj.height);
    char *jsonStr = cJSON_PrintUnformatted(json);
    if (jsonStr == nullptr) {
        EDMLOGE("ScreenWatermarkImageSerializer::Serialize print json error");
        cJSON_Delete(json);
        return false;
    }
    policy = std::string(jsonStr);
    cJSON_Delete(json);
    cJSON_free(jsonStr);
    return true;
}

bool ScreenWatermarkImageSerializer::GetPolicy(MessageParcel &data, WatermarkImageType &result)
{
    return true;
}

bool ScreenWatermarkImageSerializer::WritePolicy(MessageParcel &reply, WatermarkImageType &result)
{
    return true;
}

bool ScreenWatermarkImageSerializer::MergePolicy(std::vector<WatermarkImageType> &data,
    WatermarkImageType &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS
