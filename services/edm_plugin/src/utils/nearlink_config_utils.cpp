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

#include <unistd.h>

#include "directory_ex.h"

#include "edm_log.h"
#include "nearlink_protocol_utils.h"

namespace OHOS {
namespace EDM {
const std::string CONFIG_PATH = "/data/service/el1/public/edm/config/system/all/nearlink/config.json";
const std::string CONFIG_SYSTEM_ALL_DIR = "/data/service/el1/public/edm/config/system/all";
const std::string NEARLINK_DIR = "nearlink";
const std::string SEPARATOR = "/";
const char *const PROTOCOL_DENY_LIST = "ProtocolDenyList";
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
    LoadConfig();
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
    EDMLOGI("NearlinkConfigUtils::UpdateProtocol() - userId: %s, isAdd: %d", userId.c_str(), isAdd);

    // 通用前置检查
    if (!root_ && !LoadConfig()) {
        EDMLOGE("Failed to load config before update protocol");
        return false;
    }
    if (!CheckProtocolDenyListExists()) {
        EDMLOGE("Failed to ensure PROTOCOL_DENY_LIST exists");
        return false;
    }

    // 获取 denyList 和 userItem
    cJSON *denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        EDMLOGE("PROTOCOL_DENY_LIST not found in config");
        return false;
    }
    cJSON *userItem = cJSON_GetObjectItem(denyList, userId.c_str());

    // 调用子函数处理增删逻辑
    if (isAdd) {
        return AddProtocol(protocol, userId, denyList, userItem);
    } else {
        return RemoveProtocol(protocol, userId, denyList, userItem);
    }
}

bool NearlinkConfigUtils::AddProtocol(
    const std::string &protocol, const std::string &userId, cJSON *denyList, cJSON *userItem)
{
    if (userItem && IsProtocolExist(protocol, userItem)) {
        EDMLOGI("Protocol %s already exists for user %s", protocol.c_str(), userId.c_str());
        return true;  // 协议已存在，无需添加
    }

    cJSON *protocols = cJSON_CreateString(protocol.c_str());
    if (!protocols) {
        EDMLOGE("Failed to create protocol string item");
        return false;
    }

    if (!userItem) {
        // 新增用户条目
        CJSON_CREATE_ARRAY_AND_CHECK(userItem, false);
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(protocols, userItem, false);
        if (!cJSON_AddItemToObject(denyList, userId.c_str(), userItem)) {
            EDMLOGE("cJSON_AddItemToObject Error");
            cJSON_Delete(userItem);
            return false;
        }
    } else {
        // 直接添加到现有数组
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(protocols, userItem, false);
    }
    return SaveConfig();
}

bool NearlinkConfigUtils::RemoveProtocol(
    const std::string &protocol, const std::string &userId, cJSON *denyList, cJSON *userItem)
{
    if (!userItem) {
        EDMLOGI("User %s entry does not exist, nothing to remove", userId.c_str());
        return true;
    }

    int indexToRemove = -1;
    for (int i = 0; i < cJSON_GetArraySize(userItem); ++i) {
        cJSON *item = cJSON_GetArrayItem(userItem, i);
        if (item && item->valuestring && strcmp(item->valuestring, protocol.c_str()) == 0) {
            indexToRemove = i;
            break;
        }
    }

    if (indexToRemove < 0) {
        EDMLOGI("Protocol %s not found in user %s", protocol.c_str(), userId.c_str());
        return true;  // 协议不存在，无需删除
    }

    cJSON_DeleteItemFromArray(userItem, indexToRemove);
    if (cJSON_GetArraySize(userItem) == 0) {
        cJSON_DeleteItemFromObject(denyList, userId.c_str());  // 删除空用户条目
    }
    return SaveConfig();
}

bool NearlinkConfigUtils::IsProtocolExist(const std::string &protocol, cJSON *userItem)
{
    cJSON *protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        if (strcmp(protocolItem->valuestring, protocol.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

bool NearlinkConfigUtils::CreateNearlinkConfigDir(const std::string &dir)
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

bool NearlinkConfigUtils::QueryProtocols(const std::string &userId, std::vector<int32_t> &protocols)
{
    if (!root_ && !LoadConfig()) {
        return false;
    }
    cJSON *denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        return true;
    }
    cJSON *userItem = cJSON_GetObjectItem(denyList, userId.c_str());
    if (!userItem) {
        return true;
    }
    cJSON *protocolItem = nullptr;
    cJSON_ArrayForEach(protocolItem, userItem) {
        int32_t protocol = 0;
        NearlinkProtocolUtils::StrToProtocolInt(protocolItem->valuestring, protocol);
        protocols.push_back(protocol);
    }
    return true;
}

bool NearlinkConfigUtils::RemoveUserIdItem(const std::string &userId)
{
    EDMLOGI("NearlinkConfigUtils::RemoveUserIdItem");
    if (!root_ && !LoadConfig()) {
        return false;
    }
    cJSON *denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        return true;
    }
    cJSON_DeleteItemFromObject(denyList, userId.c_str());
    return SaveConfig();
}

bool NearlinkConfigUtils::RemoveProtocolDenyList()
{
    EDMLOGI("NearlinkConfigUtils::RemoveProtocolDenyList");
    if (!root_ && !LoadConfig()) {
        return false;
    }
    cJSON_DeleteItemFromObject(root_, PROTOCOL_DENY_LIST);
    return SaveConfig();
}

bool NearlinkConfigUtils::LoadConfig()
{
    EDMLOGI("NearlinkConfigUtils::LoadConfig");
    std::ifstream inFile(CONFIG_PATH, std::ios::binary);
    if (inFile.good()) {
        EDMLOGI("NearlinkConfigUtils::LoadConfig inFile.good");
        inFile.seekg(0, std::ios::end);
        size_t size = inFile.tellg();
        if (size == 0) {
            inFile.close();
            CJSON_CREATE_OBJECT_AND_CHECK(root_, false);
            return true;
        }
        inFile.seekg(0, std::ios::beg);
        std::string jsonStr(size, ' ');
        inFile.read(&jsonStr[0], size);
        inFile.close();
        root_ = cJSON_Parse(jsonStr.c_str());
        return root_ != nullptr;
    }
    EDMLOGI("NearlinkConfigUtils::LoadConfig inFile fail");
    inFile.close();
    CJSON_CREATE_OBJECT_AND_CHECK(root_, false);
    return true;
}

bool NearlinkConfigUtils::SaveConfig()
{
    EDMLOGI("NearlinkConfigUtils::saveConfig");
    if (!root_) {
        return false;
    }
    char *jsonStr = cJSON_Print(root_);
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

bool NearlinkConfigUtils::CheckProtocolDenyListExists()
{
    if (!root_) {
        CJSON_CREATE_OBJECT_AND_CHECK(root_, false);
    }
    cJSON *denyList = cJSON_GetObjectItem(root_, PROTOCOL_DENY_LIST);
    if (!denyList) {
        cJSON *protocolDenyList = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK(protocolDenyList, false);
        if (!cJSON_AddItemToObject(root_, PROTOCOL_DENY_LIST, protocolDenyList)) {
            EDMLOGE("NearlinkConfigUtils::cJSON_AddItemToObject Root Error");
            cJSON_Delete(protocolDenyList);
            return false;
        }
    }
    return true;
}
}  // namespace EDM
}  // namespace OHOS