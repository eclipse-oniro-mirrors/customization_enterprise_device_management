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

#include "bluetooth_config_utils.h"

#include "bt_protocol_utils.h"
#include "directory_ex.h"
#include "edm_log.h"
#include <unistd.h>

namespace OHOS {
namespace EDM {
const std::string CONFIG_PATH = "/data/service/el1/public/edm/config/system/all/bluetooth/config.json";
const std::string CONFIG_SYSTEM_ALL_DIR = "/data/service/el1/public/edm/config/system/all";
const std::string BLUETOOTH_DIR = "bluetooth";
const std::string SEPARATOR = "/";
const char* const PROTOCOL_DENY_LIST = "ProtocolDenyList";
constexpr int32_t EDM_UID = 3057;
constexpr int32_t EDM_GID = 3057;

BluetoothConfigUtils::BluetoothConfigUtils()
{
    EDMLOGI("BluetoothConfigUtils::BluetoothConfigUtils()");
    std::vector<std::string> files;
    OHOS::GetDirFiles(CONFIG_SYSTEM_ALL_DIR, files);
    if (std::find(files.begin(), files.end(), BLUETOOTH_DIR) == files.end()) {
        CreateBluetoothConfigDir(CONFIG_SYSTEM_ALL_DIR + SEPARATOR + BLUETOOTH_DIR);
    }
    LoadConfig();
}

BluetoothConfigUtils::~BluetoothConfigUtils()
{
    EDMLOGI("BluetoothConfigUtils::~BluetoothConfigUtils()");
    if (root_) {
        cJSON_Delete(root_);
    }
}

bool BluetoothConfigUtils::UpdateProtocol(const std::string &userId, const std::string &protocol, bool isAdd)
{
    EDMLOGI("BluetoothConfigUtils::BluetoothConfigUtils()");
    if (!root_ && !LoadConfig()) {
        return false;
    }
    CheckProtocolDenyListExists();
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    cJSON* userItem = cJSON_GetObjectItem(denyList, userId.c_str());
    if (isAdd) {
        if (!userItem) {
            userItem = cJSON_CreateArray();
            cJSON_AddItemToArray(userItem, cJSON_CreateString(protocol.c_str()));
            cJSON_AddItemToObject(denyList, userId.c_str(), userItem);
        } else {
            if (IsProtocolExist(protocol, userItem)) {
                return true;
            }
            cJSON_AddItemToArray(userItem, cJSON_CreateString(protocol.c_str()));
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

bool BluetoothConfigUtils::IsProtocolExist(const std::string &protocol, cJSON* userItem)
{
    cJSON* protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        if (strcmp(protocolItem->valuestring, protocol.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

bool BluetoothConfigUtils::CreateBluetoothConfigDir(const std::string dir)
{
    EDMLOGI("BluetoothConfigUtils::CreateBluetoothConfigDir");
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

bool BluetoothConfigUtils::QueryProtocols(const std::string& userId, std::vector<int32_t> &protocols)
{
    if (!root_ && !LoadConfig()) {
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
    cJSON* protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        int32_t protocol = 0;
        BtProtocolUtils::StrToProtocolInt(protocolItem->valuestring, protocol);
        protocols.push_back(protocol);
    }
    return true;
}

bool BluetoothConfigUtils::RemoveUserIdItem(const std::string &userId)
{
    EDMLOGI("BluetoothConfigUtils::RemoveUserIdItem");
    if (!root_ && !LoadConfig()) {
        return false;
    }
    cJSON* denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        return true;
    }
    cJSON_DeleteItemFromObject(denyList, userId.c_str());
    return SaveConfig();
}

bool BluetoothConfigUtils::RemoveProtocolDenyList()
{
    EDMLOGI("BluetoothConfigUtils::RemoveProtocolDenyList");
    if (!root_ && !LoadConfig()) {
        return false;
    }
    cJSON_DeleteItemFromObject(root_, PROTOCOL_DENY_LIST);
    return SaveConfig();
}

bool BluetoothConfigUtils::LoadConfig()
{
    EDMLOGI("BluetoothConfigUtils::loadConfig");
    std::ifstream inFile(CONFIG_PATH, std::ios::binary);
    if (inFile.good()) {
        EDMLOGI("BluetoothConfigUtils::loadConfig inFile.good");
        inFile.seekg(0, std::ios::end);
        std::streamsize size = inFile.tellg();
        if (size <= 0) {
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
    EDMLOGI("BluetoothConfigUtils::loadConfig inFile fail");
    inFile.close();
    root_ = cJSON_CreateObject();
    return true;
}

bool BluetoothConfigUtils::SaveConfig()
{
    EDMLOGI("BluetoothConfigUtils::saveConfig");
    if (!root_) {
        return false;
    }
    char* jsonStr = cJSON_Print(root_);
    if (!jsonStr) {
        return false;
    }
    std::ofstream file(CONFIG_PATH);
    if (!file.is_open()) {
        cJSON_free(jsonStr);
        return false;
    }
    file << jsonStr;
    file.close();
    cJSON_free(jsonStr);
    return true;
}

void BluetoothConfigUtils::CheckProtocolDenyListExists()
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