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
 
#include "password_policy_utils.h"
 
#include <unistd.h>
 
#include "cjson_check.h"
#include "directory_ex.h"
#include "edm_log.h"
 
namespace OHOS {
namespace EDM {
const std::string CONFIG_PATH = "/data/service/el1/public/edm/config/system/all/security/passwordPolicy.json";
const std::string CONFIG_SYSTEM_ALL_DIR = "/data/service/el1/public/edm/config/system/all";
const std::string SECURITY_DIR = "security";
const std::string SEPARATOR = "/";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;
const std::string COMPLEXITY_REG = "complexityReg";
const std::string VALIDITY_PERIOD = "validityPeriod";
const std::string ADDITIONAL_DESCRIPTION = "additionalDescription";
 
PasswordPolicyUtils::PasswordPolicyUtils()
{
    EDMLOGI("PasswordPolicyUtils::PasswordPolicyUtils()");
    std::vector<std::string> files;
    OHOS::GetDirFiles(CONFIG_SYSTEM_ALL_DIR, files);
    if (std::find(files.begin(), files.end(), SECURITY_DIR) == files.end()) {
        CreateConfigDir(CONFIG_SYSTEM_ALL_DIR + SEPARATOR + SECURITY_DIR);
    }
    std::string jsonStr;
    if (LoadConfig(jsonStr)) {
        root_ = cJSON_Parse(jsonStr.c_str());
    }
}
 
bool PasswordPolicyUtils::CreateConfigDir(const std::string &dir)
{
    EDMLOGI("PasswordPolicyUtils::CreateConfigDir");
    if (!OHOS::ForceCreateDirectory(dir)) {
        EDMLOGE("mkdir dir failed");
        return false;
    }
    if (chown(dir.c_str(), EDM_UID, EDM_GID) != 0) {
        EDMLOGE("fail to change dir ownership");
        return false;
    }
    mode_t mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
    if (!OHOS::ChangeModeFile(dir, mode)) {
        EDMLOGE("change mode failed, temp install dir");
        return false;
    }
    return true;
}
 
PasswordPolicyUtils::~PasswordPolicyUtils()
{
    EDMLOGI("PasswordPolicyUtils::~PasswordPolicyUtils()");
    if (root_) {
        cJSON_Delete(root_);
    }
}
 
bool PasswordPolicyUtils::UpdatePasswordPolicy(PasswordPolicy &policy)
{
    EDMLOGI("PasswordPolicyUtils::UpdatePasswordPolicy()");
    // 通用前置检查
    if (root_ == nullptr) {
        CJSON_CREATE_OBJECT_AND_CHECK(root_, false);
    }
    cJSON_DeleteItemFromObject(root_, COMPLEXITY_REG.c_str());
    cJSON_DeleteItemFromObject(root_, VALIDITY_PERIOD.c_str());
    cJSON_DeleteItemFromObject(root_, ADDITIONAL_DESCRIPTION.c_str());
    cJSON_AddStringToObject(root_, COMPLEXITY_REG.c_str(), policy.complexityReg.c_str());
    cJSON_AddNumberToObject(root_, VALIDITY_PERIOD.c_str(), policy.validityPeriod);
    cJSON_AddStringToObject(root_, ADDITIONAL_DESCRIPTION.c_str(), policy.additionalDescription.c_str());
    return SaveConfig();
}
 
bool PasswordPolicyUtils::GetPasswordPolicy(PasswordPolicy &policy)
{
    EDMLOGI("PasswordPolicyUtils::GetPasswordPolicy()");
    // 通用前置检查
    if (root_ == nullptr) {
        std::string jsonStr;
        if (!LoadConfig(jsonStr)) {
            EDMLOGW("Failed to load config before update protocol");
            return true;
        }
        root_ = cJSON_Parse(jsonStr.c_str());
        if (root_ == nullptr) {
            EDMLOGE("Failed to load config, root is null");
            return false;
        }
    }
    cJSON *complexityReg = cJSON_GetObjectItem(root_, COMPLEXITY_REG.c_str());
    cJSON *validityPeriod = cJSON_GetObjectItem(root_, VALIDITY_PERIOD.c_str());
    cJSON *additionalDescription = cJSON_GetObjectItem(root_, ADDITIONAL_DESCRIPTION.c_str());
    if (!cJSON_IsString(complexityReg) || !cJSON_IsNumber(validityPeriod)) {
        return false;
    }
    if (additionalDescription != nullptr && !cJSON_IsString(additionalDescription)) {
        return false;
    }
    policy.complexityReg = cJSON_GetStringValue(complexityReg);
    policy.validityPeriod = cJSON_GetNumberValue(validityPeriod);
    if (additionalDescription == nullptr) {
        policy.additionalDescription = "";
    } else {
        policy.additionalDescription = cJSON_GetStringValue(additionalDescription);
    }
    return true;
}
 
bool PasswordPolicyUtils::LoadConfig(std::string &jsonStr)
{
    EDMLOGI("PasswordPolicyUtils::LoadConfig");
    std::ifstream inFile(CONFIG_PATH, std::ios::binary);
    if (inFile.good()) {
        EDMLOGI("PasswordPolicyUtils::LoadConfig inFile.good");
        inFile.seekg(0, std::ios::end);
        size_t size = static_cast<size_t>(inFile.tellg());
        if (size == 0) {
            EDMLOGW("PasswordPolicyUtils::LoadConfig config is empty");
            inFile.close();
            return false;
        }
        inFile.seekg(0, std::ios::beg);
        jsonStr.assign(size, ' ');
        inFile.read(&jsonStr[0], size);
        inFile.close();
        return true;
    }
    EDMLOGI("PasswordPolicyUtils::LoadConfig inFile fail");
    inFile.close();
    return false;
}
 
bool PasswordPolicyUtils::SaveConfig()
{
    EDMLOGI("PasswordPolicyUtils::saveConfig");
    if (!root_) {
        EDMLOGI("PasswordPolicyUtils::SaveConfig error root is null");
        return false;
    }
    char *jsonStr = cJSON_Print(root_);
    if (!jsonStr) {
        EDMLOGI("PasswordPolicyUtils::SaveConfig error jsonStr is null");
        return false;
    }
    std::ofstream file(CONFIG_PATH);
    if (!file.is_open()) {
        EDMLOGI("PasswordPolicyUtils::SaveConfig open file is error");
        cJSON_free(jsonStr);
        return false;
    }
    file << jsonStr;
    file.close();
    cJSON_free(jsonStr);
    return true;
}
}  // namespace EDM
}  // namespace OHOS