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

#include "nearlink_config_utils.h"

#include "nearlink_protocol_utils.h"
#include "directory_ex.h"
#include "edm_log.h"
#include <unistd.h>

namespace OHOS {
namespace EDM {
const std::string CONFIG_PATH = "/data/service/el1/public/edm/config/system/all/nearlink/config.json";
const std::string CONFIG_SYSTEM_ALL_DIR = "/data/service/el1/public/edm/config/system/all";
const std::string NEARLINK_DIR = "nearlink";
const std::string SEPARATOR = "/";
const char* const PROTOCOL_DENY_LIST = "ProtocolDenyList";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;

NearlinkConfigUtils::NearlinkConfigUtils()
{
    EDMLOGI("NearlinkConfigUtils::NearlinkConfigUtils()");
    std::vector<std::string> files;
    OHOS::GetDirFiles(CONFIG_SYSTEM_ALL_DIR, files);
    if (std::find(files.begin(), files.end(), NEARLINK_DIR) == files.end()) {
        CreateNearlinkConfigDir(CONFIG_SYSTEM_ALL_DIR + SEPARATOR + NEARLINK_DIR);
    }
    loadConfig();
}

NearlinkConfigUtils::~NearlinkConfigUtils()
{
    EDMLOGI("NearlinkConfigUtils::~NearlinkConfigUtils()");
    if (root_) {
        cJSON_Delete(root_);
    }
}

bool NearlinkConfigUtils::UpdateProtocol(const std::string &userId, const std::string &protocol, bool isAdd)
{
    EDMLOGI("NearlinkConfigUtils::UpdateProtocol()");
    if (!root_ && !loadConfig()) {
        return false;
    }
    CheckProtocolDenyListExists();
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    cJSON* userItem = cJSON_GetObjectItem(denyList, userId.c_str());
    if (isAdd) {
        cJSON* protocols =  cJSON_CreateString(protocol.c_str());
        if (!userItem) {
            userItem = cJSON_CreateArray();
            cJSON_bool resultAddArray = cJSON_AddItemToArray(userItem, protocols);
            if (resultAddArray == cJSON_False) {
                cJSON_Delete(userItem);
                cJSON_Delete(protocols);
            }
            cJSON_bool resultAddObj = cJSON_AddItemToObject(denyList, userId.c_str(), userItem);
            if (resultAddObj == cJSON_False) {
                cJSON_Delete(userItem);
            }
        } else {
            if (IsProtocolExist(protocol, userItem)) {
                return true;
            }
            cJSON_bool resultAddArray = cJSON_AddItemToArray(userItem, protocols);
            if (resultAddArray == cJSON_False) {
                cJSON_Delete(protocols);
            }
        }
    } else {
        if (!userItem) {
            return true;
        }

        int indexToRemove = -1;
        for (int i = 0; i < cJSON_GetArraySize(userItem); ++i) {
            cJSON* item = cJSON_GetArrayItem(userItem, i);
            if (strcmp(item->valuestring, protocol.c_str()) == 0) {
                indexToRemove = i;
                break;
            }
        }

        if (indexToRemove >= 0) {
            cJSON_DeleteItemFromArray(userItem, indexToRemove);
        }

        if (cJSON_GetArraySize(userItem) == 0) {
            cJSON_DeleteItemFromObject(denyList, userId.c_str());
        }
    }
    return SaveConfig();
}

bool NearlinkConfigUtils::IsProtocolExist(const std::string &protocol, cJSON* userItem)
{
    cJSON* protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        if (strcmp(protocolItem->valuestring, protocol.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

bool NearlinkConfigUtils::CreateNearlinkConfigDir(const std::string dir)
{
    EDMLOGI("NearlinkConfigUtils::CreateNearlinkConfigDir");
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

bool NearlinkConfigUtils::queryProtocols(const std::string& userId, std::vector<int32_t> &protocols)
{
    if (!root_ && !loadConfig()) {
        return false;
    }
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        return true;
    }
    cJSON* userItem = cJSON_GetObjectItem(denyList, userId.c_str());
    if (!userItem) {
        return true;
    }
    NearlinkProtocolUtils nearlinkProtocolUtils;
    cJSON* protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        int32_t protocol = 0;
        nearlinkProtocolUtils.StrToProtocolInt(protocolItem->valuestring, protocol);
        protocols.push_back(protocol);
    }
    return true;
}

bool NearlinkConfigUtils::RemoveUserIdItem(const std::string &userId)
{
    EDMLOGI("NearlinkConfigUtils::RemoveUserIdItem");
    if (!root_ && !loadConfig()) {
        return false;
    }
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        return true;
    }
    cJSON_DeleteItemFromObject(denyList, userId.c_str());
    return SaveConfig();
}

bool NearlinkConfigUtils::RemoveProtocolDenyList()
{
    EDMLOGI("NearlinkConfigUtils::RemoveProtocolDenyList");
    if (!root_ && !loadConfig()) {
        return false;
    }
    cJSON_DeleteItemFromObject(root_, PROTOCOL_DENY_LIST);
    return SaveConfig();
}

bool NearlinkConfigUtils::loadConfig()
{
    EDMLOGI("NearlinkConfigUtils::loadConfig");
    std::ifstream inFile(CONFIG_PATH, std::ios::binary);
    if (inFile.good()) {
    EDMLOGI("NearlinkConfigUtils::loadConfig inFile.good");
        inFile.seekg(0, std::ios::end);
        size_t size = inFile.tellg();
        if (size == 0) {
            inFile.close();
            root_ = cJSON_CreateObject();
            return true;
        }
        inFile.seekg(0, std::ios::beg);
        std::string jsonStr(size, ' ');
        inFile.read(&jsonStr[0], size);
        inFile.close();
        root_ = cJSON_Parse(jsonStr.c_str());
        return root_ != nullptr;
    }
    EDMLOGI("NearlinkConfigUtils::loadConfig inFile fail");
    inFile.close();
    root_ = cJSON_CreateObject();
    return true;
}

bool NearlinkConfigUtils::SaveConfig()
{
    EDMLOGI("NearlinkConfigUtils::saveConfig");
    if (!root_) {
        return false;
    }
    char* jsonStr = cJSON_Print(root_);
    if (!jsonStr) {
        return false;
    }
    std::ofstream file(CONFIG_PATH);
    if (!file.is_open()) {
        free(jsonStr);
        return false;
    }
    file << jsonStr;
    file.close();
    free(jsonStr);
    return true;
}

void NearlinkConfigUtils::CheckProtocolDenyListExists()
{
    if (!root_) {
        root_ = cJSON_CreateObject();
    }
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        cJSON_AddItemToObject(root_, PROTOCOL_DENY_LIST, cJSON_CreateObject());
    }
}
} // namespace EDM
} // namespace OHOS