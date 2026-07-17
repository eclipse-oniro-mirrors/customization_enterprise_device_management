/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "installed_bundle_info_util.h"

#include <chrono>
#include <fstream>
#include <algorithm>
#include <unistd.h>
#include <sys/stat.h>

#include "cjson_check.h"
#include "directory_ex.h"
#include "edm_log.h"
#include "hisysevent_adapter.h"

namespace OHOS {
namespace EDM {
constexpr size_t MAX_BUNDLE_INFO_COUNT = 20;
constexpr const char* EDM_DIR = "/data/service/el1/public/edm";
constexpr const char* BUNDLE_INFO_FILE_PATH = "/data/service/el1/public/edm/installed_bundle_info.json";
constexpr uint64_t TIMER_DELAY_MS = 6 * 3600 * 1000;
constexpr const char* JSON_KEY_MDM_NAME = "mdmName";
constexpr const char* JSON_KEY_INSTALLED_NAME = "installedName";
constexpr const char* JSON_KEY_INSTALLED_TYPE = "installedType";
constexpr const char* JSON_KEY_INSTALLED_TIME = "installedTime";

bool InstalledBundleInfoUtil::EnsureFileExists()
{
    if (!OHOS::ForceCreateDirectory(EDM_DIR)) {
        EDMLOGE("InstalledBundleInfoUtil ForceCreateDirectory failed");
        return false;
    }
    if (access(BUNDLE_INFO_FILE_PATH, F_OK) == 0) {
        return true;
    }
    std::ofstream file(BUNDLE_INFO_FILE_PATH, std::ios::out);
    if (!file.is_open()) {
        EDMLOGE("InstalledBundleInfoUtil create file failed");
        return false;
    }
    file << "[]";
    file.close();
    if (chmod(BUNDLE_INFO_FILE_PATH, S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
        EDMLOGE("InstalledBundleInfoUtil chmod failed");
        return false;
    }
    return true;
}

bool InstalledBundleInfoUtil::LoadFromFile(std::vector<InstalledBundleInfo> &infoList)
{
    std::ifstream file(BUNDLE_INFO_FILE_PATH);
    if (!file.is_open()) {
        EDMLOGE("InstalledBundleInfoUtil open file for read failed");
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    if (content.empty()) {
        return true;
    }
    cJSON *root = cJSON_Parse(content.c_str());
    if (root == nullptr) {
        EDMLOGE("InstalledBundleInfoUtil parse json failed");
        return false;
    }
    if (!cJSON_IsArray(root)) {
        EDMLOGE("InstalledBundleInfoUtil json is not array");
        cJSON_Delete(root);
        return false;
    }
    int size = cJSON_GetArraySize(root);
    int maxLoadCount = 100;
    for (int i = 0; i < size && i < maxLoadCount; ++i) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (item == nullptr) {
            continue;
        }
        InstalledBundleInfo info;
        cJSON *mdmName = cJSON_GetObjectItem(item, JSON_KEY_MDM_NAME);
        info.mdmName = (mdmName != nullptr && cJSON_IsString(mdmName) && mdmName->valuestring != nullptr)
            ? mdmName->valuestring : "";
        cJSON *installedName = cJSON_GetObjectItem(item, JSON_KEY_INSTALLED_NAME);
        info.installedName = (installedName != nullptr && cJSON_IsString(installedName) &&
            installedName->valuestring != nullptr) ? installedName->valuestring : "";
        cJSON *installedType = cJSON_GetObjectItem(item, JSON_KEY_INSTALLED_TYPE);
        info.installedType = (installedType != nullptr && cJSON_IsNumber(installedType))
            ? static_cast<InstalledBundleType>(installedType->valueint) : InstalledBundleType::NORMAL;
        cJSON *installedTime = cJSON_GetObjectItem(item, JSON_KEY_INSTALLED_TIME);
        info.installedTime = (installedTime != nullptr  && cJSON_IsNumber(installedTime))
            ? static_cast<int64_t>(installedTime->valuedouble) : 0;
        infoList.push_back(info);
    }
    cJSON_Delete(root);
    return true;
}

bool InstalledBundleInfoUtil::SaveToFile(const std::vector<InstalledBundleInfo> &infoList)
{
    std::string jsonStr = SerializeToJson(infoList);
    if (jsonStr.empty() && !infoList.empty()) {
        EDMLOGE("InstalledBundleInfoUtil serialize json failed");
        return false;
    }
    std::ofstream file(BUNDLE_INFO_FILE_PATH, std::ios::trunc);
    if (!file.is_open()) {
        EDMLOGE("InstalledBundleInfoUtil open file for write failed");
        return false;
    }
    file << jsonStr;
    file.close();
    return true;
}

std::string InstalledBundleInfoUtil::SerializeToJson(const std::vector<InstalledBundleInfo> &infoList)
{
    cJSON *root;
    CJSON_CREATE_ARRAY_AND_CHECK(root, "");
    for (const auto &info : infoList) {
        cJSON *item;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, "", root);
        if (!cJSON_AddStringToObject(item, JSON_KEY_MDM_NAME, info.mdmName.c_str()) ||
            !cJSON_AddStringToObject(item, JSON_KEY_INSTALLED_NAME, info.installedName.c_str()) ||
            !cJSON_AddNumberToObject(item, JSON_KEY_INSTALLED_TYPE, static_cast<int32_t>(info.installedType)) ||
            !cJSON_AddNumberToObject(item, JSON_KEY_INSTALLED_TIME, info.installedTime)) {
            cJSON_Delete(item);
            cJSON_Delete(root);
            return "";
        }
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(item, root, "");
    }
    char *jsonStr = cJSON_PrintUnformatted(root);
    std::string result = (jsonStr != nullptr) ? std::string(jsonStr) : "";
    cJSON_Delete(root);
    if (jsonStr != nullptr) {
        cJSON_free(jsonStr);
    }
    return result;
}

bool InstalledBundleInfoUtil::AddInstalledBundleInfo(const std::string &mdmName,
    const std::string &installedName, InstalledBundleType installedType)
{
    std::unique_lock<std::mutex> lock(fileMutex_);
    if (!EnsureFileExists()) {
        return false;
    }
    std::vector<InstalledBundleInfo> infoList;
    if (!LoadFromFile(infoList)) {
        return false;
    }
    InstalledBundleInfo info;
    info.mdmName = mdmName;
    info.installedName = installedName;
    info.installedType = installedType;
    info.installedTime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    infoList.push_back(info);
    if (!SaveToFile(infoList)) {
        return false;
    }
    if (infoList.size() >= MAX_BUNDLE_INFO_COUNT) {
        ReportAndClearLocked(lock);
    } else {
        ScheduleReportIfNeeded();
    }
    return true;
}

size_t InstalledBundleInfoUtil::GetInstalledBundleInfoCount()
{
    std::lock_guard<std::mutex> lock(fileMutex_);
    std::vector<InstalledBundleInfo> infoList;
    if (!LoadFromFile(infoList)) {
        return 0;
    }
    return infoList.size();
}

bool InstalledBundleInfoUtil::HasInstalledBundleInfo()
{
    return GetInstalledBundleInfoCount() > 0;
}

bool InstalledBundleInfoUtil::ClearInstalledBundleInfoLocked()
{
    std::ofstream file(BUNDLE_INFO_FILE_PATH, std::ios::trunc);
    if (!file.is_open()) {
        EDMLOGE("InstalledBundleInfoUtil clear file failed");
        return false;
    }
    file << "[]";
    file.close();
    return true;
}

bool InstalledBundleInfoUtil::SwapAndClearLocked(std::vector<InstalledBundleInfo> &outList)
{
    if (!LoadFromFile(outList)) {
        return false;
    }
    if (outList.empty()) {
        return false;
    }
    return ClearInstalledBundleInfoLocked();
}

bool InstalledBundleInfoUtil::RestoreToFileLocked(const std::vector<InstalledBundleInfo> &savedList)
{
    std::vector<InstalledBundleInfo> currentList;
    LoadFromFile(currentList);
    size_t maxCount = 100;
    size_t restoreCount = std::min(savedList.size(), maxCount);
    currentList.insert(currentList.begin(), savedList.begin(), savedList.begin() + restoreCount);
    return SaveToFile(currentList);
}

void InstalledBundleInfoUtil::ScheduleReportIfNeeded()
{
    EDMLOGI("InstalledBundleInfoUtil::ScheduleReportIfNeeded");
    auto timer = IEdmTimerManager::GetInstance();
    if (timer == nullptr || timer->IsTimerRunning(EdmTimerTask::INSTALLED_BUNDLE_TIMER)) {
        return;
    }
    timer->SetTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER, TIMER_DELAY_MS, [this]() {
        InstalledBundleInfoUtil::GetInstance()->ReportAndClear();
    });
}

void InstalledBundleInfoUtil::ReportAndClearLocked(std::unique_lock<std::mutex> &lock)
{
    EDMLOGI("InstalledBundleInfoUtil::ReportAndClearLocked");
    std::vector<InstalledBundleInfo> savedList;
    if (!SwapAndClearLocked(savedList)) {
        return;
    }
    lock.unlock();
    std::string installedInfo = SerializeToJson(savedList);
    bool ret = HiSysEventAdapter::ReportInstalledBundleInfo(installedInfo);
    if (ret) {
        auto timer = IEdmTimerManager::GetInstance();
        if (timer != nullptr) {
            timer->CancelTimer(EdmTimerTask::INSTALLED_BUNDLE_TIMER);
        }
    } else {
        lock.lock();
        RestoreToFileLocked(savedList);
    }
}

void InstalledBundleInfoUtil::ReportAndClear()
{
    EDMLOGI("InstalledBundleInfoUtil::ReportAndClear");
    std::unique_lock<std::mutex> lock(fileMutex_);
    ReportAndClearLocked(lock);
}
} // namespace EDM
} // namespace OHOS