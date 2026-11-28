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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_BACKUP_DATA_CODEC_H
#define SERVICES_EDM_INCLUDE_ADMIN_BACKUP_DATA_CODEC_H

#include <cstdint>
#include <string>
#include <vector>

#include "edm_errors.h"

namespace OHOS {
namespace EDM {

struct AdminBackupItem {
    std::string bundleName;
    std::string abilityName;
    int32_t userId = 0;
    int32_t adminType = 0;
    int32_t enableSource = 0;
    bool isDebug = false;
};

struct BackupPayload {
    int32_t version = 1;
    std::string deviceId;
    std::vector<AdminBackupItem> admins;
};

struct RestoreItem {
    std::string bundleName;
    std::string expectType;
    std::string result;
    int32_t errorCode = 0;
    std::string errorInfo;
    bool idempotent = false; // 幂等命中（已激活且与备份一致），计入 CountInfo.duplicateCount
};

struct RestoreSummary {
    int32_t errorCode = 0;
    std::string errorInfo;
    int32_t succeeded = 0;
    int32_t duplicateCount = 0; // 幂等命中数
    int32_t failed = 0;
    std::vector<RestoreItem> details;
};

struct BackupResult {
    int32_t errorCode = 0;
    std::string errorInfo;
    int32_t adminCount = 0;
};

class AdminBackupDataCodec {
public:
    static AdminBackupDataCodec* GetInstance();

    bool Serialize(const BackupPayload &payload, std::vector<uint8_t> &outBytes);
    bool Deserialize(const std::vector<uint8_t> &bytes, BackupPayload &outPayload);
    ErrCode ReadAll(int32_t fd, std::vector<uint8_t> &outData);
    ErrCode WriteAll(int32_t fd, const std::vector<uint8_t> &data);
    std::string SerializeBackupResult(const BackupResult &result);
    std::string SerializeRestoreSummary(const RestoreSummary &summary);
    std::string SerializeErrorResult(uint32_t errorCode, const std::string &errorInfo);
    static std::string AdminTypeToString(int32_t adminType);

private:
    AdminBackupDataCodec() = default;
    ~AdminBackupDataCodec() = default;
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_BACKUP_DATA_CODEC_H
