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

#include "password_policy_serializer.h"

#include "cJSON.h"

namespace OHOS {
namespace EDM {
const std::string COMPLEXITY_REG = "complexityReg";
const std::string VALIDITY_PERIOD = "validityPeriod";
const std::string ADDITIONAL_DESCRIPTION = "additionalDescription";

bool PasswordSerializer::Deserialize(const std::string &jsonString, PasswordPolicy &policy)
{
    if (jsonString.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        return false;
    }
    cJSON* complexityReg = cJSON_GetObjectItem(root, COMPLEXITY_REG.c_str());
    cJSON* validityPeriod = cJSON_GetObjectItem(root, VALIDITY_PERIOD.c_str());
    cJSON* additionalDescription = cJSON_GetObjectItem(root, ADDITIONAL_DESCRIPTION.c_str());
    if (complexityReg == nullptr || validityPeriod == nullptr
        || additionalDescription == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    policy.complexityReg = cJSON_GetStringValue(complexityReg);
    policy.validityPeriod = cJSON_GetNumberValue(validityPeriod);
    policy.additionalDescription = cJSON_GetStringValue(additionalDescription);
    cJSON_Delete(root);
    EDMLOGI("PasswordSerializer::Deserialize %{public}s", jsonString.c_str());
    return true;
}

bool PasswordSerializer::Serialize(const PasswordPolicy &policy, std::string &jsonString)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, COMPLEXITY_REG.c_str(), policy.complexityReg.c_str());
    cJSON_AddNumberToObject(root, VALIDITY_PERIOD.c_str(), policy.validityPeriod);
    cJSON_AddStringToObject(root, ADDITIONAL_DESCRIPTION.c_str(), policy.additionalDescription.c_str());
    char *cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        jsonString = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    EDMLOGI("PasswordSerializer::Deserialize %{public}s", jsonString.c_str());
    return true;
}

bool PasswordSerializer::GetPolicy(MessageParcel &data, PasswordPolicy &result)
{
    result.complexityReg = data.ReadString();
    result.validityPeriod = data.ReadInt32();
    result.additionalDescription = data.ReadString();
    return true;
}

bool PasswordSerializer::WritePolicy(MessageParcel &reply, PasswordPolicy &result)
{
    return true;
}

bool PasswordSerializer::MergePolicy(std::vector<PasswordPolicy> &data, PasswordPolicy &result)
{
    if (data.empty()) {
        return false;
    }
    result = data.back();
    return true;
}
} // namespace EDM
} // namespace OHOS