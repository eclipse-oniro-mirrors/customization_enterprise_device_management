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

#include "admin_backup_data_codec.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#include "admin_type.h"
#include "backup_error_mapper.h"
#include "cJSON.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

namespace {
constexpr int32_t READ_BUFFER_SIZE = 64 * 1024; // 64 KiB
constexpr int32_t SUPPORTED_BACKUP_PAYLOAD_VERSION = 1;
constexpr const char* KEY_VERSION = "version";
constexpr const char* KEY_DEVICE_ID = "deviceId";
constexpr const char* KEY_ADMINS = "admins";
constexpr const char* KEY_BUNDLE_NAME = "bundleName";
constexpr const char* KEY_ABILITY_NAME = "abilityName";
constexpr const char* KEY_USER_ID = "userId";
constexpr const char* KEY_ADMIN_TYPE = "adminType";
constexpr const char* KEY_ENABLE_SOURCE = "enableSource";
constexpr const char* KEY_IS_DEBUG = "isDebug";
} // namespace

AdminBackupDataCodec* AdminBackupDataCodec::GetInstance()
{
    static AdminBackupDataCodec instance;
    return &instance;
}

bool AdminBackupDataCodec::Serialize(const BackupPayload &payload, std::vector<uint8_t> &outBytes)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        EDMLOGE("Serialize: create root failed");
        return false;
    }
    cJSON_AddNumberToObject(root, KEY_VERSION, payload.version);
    if (!payload.deviceId.empty()) {
        cJSON_AddStringToObject(root, KEY_DEVICE_ID, payload.deviceId.c_str());
    }
    cJSON *admins = cJSON_CreateArray();
    if (admins == nullptr) {
        cJSON_Delete(root);
        EDMLOGE("Serialize: create admins array failed");
        return false;
    }
    cJSON_AddItemToObject(root, KEY_ADMINS, admins);
    for (const auto &item : payload.admins) {
        cJSON *obj = cJSON_CreateObject();
        if (obj == nullptr) {
            cJSON_Delete(root);
            EDMLOGE("Serialize: create admin obj failed");
            return false;
        }
        cJSON_AddStringToObject(obj, KEY_BUNDLE_NAME, item.bundleName.c_str());
        cJSON_AddStringToObject(obj, KEY_ABILITY_NAME, item.abilityName.c_str());
        cJSON_AddNumberToObject(obj, KEY_USER_ID, item.userId);
        cJSON_AddNumberToObject(obj, KEY_ADMIN_TYPE, item.adminType);
        cJSON_AddNumberToObject(obj, KEY_ENABLE_SOURCE, item.enableSource);
        cJSON_AddBoolToObject(obj, KEY_IS_DEBUG, static_cast<cJSON_bool>(item.isDebug));
        cJSON_AddItemToArray(admins, obj);
    }
    char *jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        EDMLOGE("Serialize: print json failed");
        return false;
    }
    size_t len = std::strlen(jsonStr);
    outBytes.assign(reinterpret_cast<uint8_t *>(jsonStr), reinterpret_cast<uint8_t *>(jsonStr) + len);
    cJSON_free(jsonStr);
    return true;
}

namespace {
void ParseAdminItem(cJSON *item, AdminBackupItem &admin)
{
    cJSON *bn = cJSON_GetObjectItem(item, KEY_BUNDLE_NAME);
    if (bn != nullptr && cJSON_IsString(bn)) {
        admin.bundleName = bn->valuestring;
    }
    cJSON *ab = cJSON_GetObjectItem(item, KEY_ABILITY_NAME);
    if (ab != nullptr && cJSON_IsString(ab)) {
        admin.abilityName = ab->valuestring;
    }
    cJSON *uid = cJSON_GetObjectItem(item, KEY_USER_ID);
    if (uid != nullptr && cJSON_IsNumber(uid)) {
        admin.userId = uid->valueint;
    }
    cJSON *at = cJSON_GetObjectItem(item, KEY_ADMIN_TYPE);
    if (at != nullptr && cJSON_IsNumber(at)) {
        admin.adminType = at->valueint;
    }
    cJSON *es = cJSON_GetObjectItem(item, KEY_ENABLE_SOURCE);
    if (es != nullptr && cJSON_IsNumber(es)) {
        admin.enableSource = es->valueint;
    }
    cJSON *dbg = cJSON_GetObjectItem(item, KEY_IS_DEBUG);
    if (dbg != nullptr) {
        admin.isDebug = cJSON_IsTrue(dbg);
    }
}
} // namespace

bool AdminBackupDataCodec::Deserialize(const std::vector<uint8_t> &bytes, BackupPayload &outPayload)
{
    if (bytes.empty()) {
        EDMLOGE("Deserialize: empty bytes");
        return false;
    }
    std::string jsonStr(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    cJSON *root = cJSON_ParseWithLength(jsonStr.c_str(), jsonStr.size());
    if (root == nullptr) {
        EDMLOGE("Deserialize: parse json failed");
        return false;
    }
    cJSON *version = cJSON_GetObjectItem(root, KEY_VERSION);
    if (version == nullptr || !cJSON_IsNumber(version) ||
        version->valueint != SUPPORTED_BACKUP_PAYLOAD_VERSION) {
        cJSON_Delete(root);
        EDMLOGE("Deserialize: unsupported payload version");
        return false;
    }
    outPayload.version = version->valueint;
    cJSON *deviceId = cJSON_GetObjectItem(root, KEY_DEVICE_ID);
    if (deviceId != nullptr && cJSON_IsString(deviceId)) {
        outPayload.deviceId = deviceId->valuestring;
    }
    cJSON *admins = cJSON_GetObjectItem(root, KEY_ADMINS);
    if (admins == nullptr || !cJSON_IsArray(admins)) {
        cJSON_Delete(root);
        EDMLOGE("Deserialize: admins missing or not an array");
        return false;
    }
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, admins)
    {
        if (!cJSON_IsObject(item)) {
            continue;
        }
        AdminBackupItem admin;
        ParseAdminItem(item, admin);
        outPayload.admins.push_back(std::move(admin));
    }
    cJSON_Delete(root);
    return true;
}

ErrCode AdminBackupDataCodec::ReadAll(int32_t fd, std::vector<uint8_t> &outData)
{
    if (fd < 0) {
        EDMLOGE("ReadAll: invalid fd %{public}d", fd);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    outData.clear();
    std::vector<uint8_t> buffer(READ_BUFFER_SIZE);
    ssize_t n = 0;
    while ((n = read(fd, buffer.data(), buffer.size())) != 0) {
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            EDMLOGE("ReadAll: read failed, errno=%{public}d", errno);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        outData.insert(outData.end(), buffer.data(), buffer.data() + n);
    }
    return ERR_OK;
}

ErrCode AdminBackupDataCodec::WriteAll(int32_t fd, const std::vector<uint8_t> &data)
{
    if (fd < 0) {
        EDMLOGE("WriteAll: invalid fd %{public}d", fd);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    size_t total = data.size();
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, data.data() + written, total - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            EDMLOGE("WriteAll: write failed, errno=%{public}d", errno);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        written += static_cast<size_t>(n);
    }
    return ERR_OK;
}

namespace {
constexpr int32_t MAX_DETAIL_COUNT = 50;

void WriteErrorInfo(cJSON *resultInfo, uint32_t errorCode, const std::string &errorInfo)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        return;
    }
    cJSON_AddStringToObject(obj, "type", "ErrorInfo");
    cJSON_AddStringToObject(obj, "errorCode", std::to_string(errorCode).c_str());
    std::string info = errorInfo.empty() ? BackupErrorMapper::GetErrorMessage(errorCode) : errorInfo;
    cJSON_AddStringToObject(obj, "errorInfo", info.c_str());
    cJSON_AddItemToArray(resultInfo, obj);
}

void WriteCountInfo(cJSON *resultInfo, int32_t successCount, int32_t duplicateCount, int32_t failedCount,
    const std::vector<std::string> &details)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        return;
    }
    cJSON_AddStringToObject(obj, "type", "CountInfo");
    cJSON *infos = cJSON_CreateArray();
    cJSON *info = cJSON_CreateObject();
    if (infos == nullptr || info == nullptr) {
        cJSON_Delete(obj);
        cJSON_Delete(infos);
        cJSON_Delete(info);
        return;
    }
    cJSON_AddStringToObject(info, "backupInfo", "edmAdmin");
    cJSON_AddNumberToObject(info, "successCount", successCount);
    cJSON_AddNumberToObject(info, "duplicateCount", duplicateCount);
    cJSON_AddNumberToObject(info, "failedCount", failedCount);
    cJSON *detailArr = cJSON_CreateArray();
    if (detailArr != nullptr) {
        cJSON_AddItemToObject(info, "details", detailArr);
        int32_t count = 0;
        for (const auto &detail : details) {
            if (++count > MAX_DETAIL_COUNT) {
                break;
            }
            cJSON_AddItemToArray(detailArr, cJSON_CreateString(detail.c_str()));
        }
    }
    cJSON_AddItemToArray(infos, info);
    cJSON_AddItemToObject(obj, "infos", infos);
    cJSON_AddItemToArray(resultInfo, obj);
}

std::string PrintResultInfo(cJSON *root)
{
    char *jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (jsonStr == nullptr) {
        return "{}";
    }
    std::string ret(jsonStr);
    cJSON_free(jsonStr);
    return ret;
}

cJSON *CreateResultInfoRoot(cJSON **outResultInfo)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return nullptr;
    }
    cJSON *resultInfo = cJSON_CreateArray();
    if (resultInfo == nullptr) {
        cJSON_Delete(root);
        return nullptr;
    }
    cJSON_AddItemToObject(root, "resultInfo", resultInfo);
    *outResultInfo = resultInfo;
    return root;
}

std::vector<std::string> CollectFailDetails(const RestoreSummary &summary)
{
    std::vector<std::string> failDetails;
    for (const auto &item : summary.details) {
        if (item.errorCode != 0) {
            failDetails.push_back(item.bundleName + ": " + std::to_string(item.errorCode));
        }
    }
    return failDetails;
}

cJSON *CreateRestoreDetailItem(const RestoreItem &item)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        return nullptr;
    }
    cJSON_AddStringToObject(obj, "bundleName", item.bundleName.c_str());
    cJSON_AddStringToObject(obj, "expectType", item.expectType.c_str());
    cJSON_AddStringToObject(obj, "result", item.result.c_str());
    cJSON_AddNumberToObject(obj, "errorCode", item.errorCode);
    std::string info = item.errorInfo.empty()
        ? BackupErrorMapper::GetErrorMessage(static_cast<uint32_t>(item.errorCode))
        : item.errorInfo;
    cJSON_AddStringToObject(obj, "errorInfo", info.c_str());
    return obj;
}

void WriteRestoreDetail(cJSON *resultInfo, const std::vector<RestoreItem> &details)
{
    cJSON *detailObj = cJSON_CreateObject();
    if (detailObj == nullptr) {
        return;
    }
    cJSON_AddStringToObject(detailObj, "type", "EdmRestoreDetail");
    cJSON *detailArr = cJSON_CreateArray();
    if (detailArr != nullptr) {
        cJSON_AddItemToObject(detailObj, "details", detailArr);
        for (const auto &item : details) {
            cJSON *obj = CreateRestoreDetailItem(item);
            if (obj != nullptr) {
                cJSON_AddItemToArray(detailArr, obj);
            }
        }
    }
    cJSON_AddItemToArray(resultInfo, detailObj);
}
} // namespace

std::string AdminBackupDataCodec::SerializeBackupResult(const BackupResult &result)
{
    cJSON *resultInfo = nullptr;
    cJSON *root = CreateResultInfoRoot(&resultInfo);
    if (root == nullptr) {
        return "{}";
    }
    // 备份为整体操作：任一步失败即整体失败，仅 ErrorInfo；成功时附 CountInfo
    WriteErrorInfo(resultInfo, static_cast<uint32_t>(result.errorCode), result.errorInfo);
    if (result.errorCode == 0) {
        WriteCountInfo(resultInfo, result.adminCount, 0, 0, {});
    }
    return PrintResultInfo(root);
}

std::string AdminBackupDataCodec::SerializeRestoreSummary(const RestoreSummary &summary)
{
    cJSON *resultInfo = nullptr;
    cJSON *root = CreateResultInfoRoot(&resultInfo);
    if (root == nullptr) {
        return "{}";
    }
    bool partial = summary.failed > 0;
    uint32_t overall = partial ? EdmReturnErrCode::BACKUP_PARTIAL_FAILED : 0;
    WriteErrorInfo(resultInfo, overall, partial ? BackupErrorMapper::GetErrorMessage(overall) : summary.errorInfo);
    WriteCountInfo(resultInfo, summary.succeeded, summary.duplicateCount, summary.failed,
        CollectFailDetails(summary));
    WriteRestoreDetail(resultInfo, summary.details);
    return PrintResultInfo(root);
}

std::string AdminBackupDataCodec::SerializeErrorResult(uint32_t errorCode, const std::string &errorInfo)
{
    cJSON *resultInfo = nullptr;
    cJSON *root = CreateResultInfoRoot(&resultInfo);
    if (root == nullptr) {
        return "{}";
    }
    WriteErrorInfo(resultInfo, errorCode, errorInfo);
    return PrintResultInfo(root);
}

std::string AdminBackupDataCodec::AdminTypeToString(int32_t adminType)
{
    switch (static_cast<AdminType>(adminType)) {
        case AdminType::ENT:
            return "SDA";
        case AdminType::NORMAL:
        case AdminType::SUB_SUPER_ADMIN:
        case AdminType::BYOD:
        default:
            return "DA";
    }
}

} // namespace EDM
} // namespace OHOS
