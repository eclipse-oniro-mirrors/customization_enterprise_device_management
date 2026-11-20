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

#ifndef SERVICES_EDM_INCLUDE_BACKUP_EXTENSION_HANDLER_H
#define SERVICES_EDM_INCLUDE_BACKUP_EXTENSION_HANDLER_H

#include <string>
#include <vector>

#include "admin_backup_data_codec.h"
#include "edm_errors.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {

class BackupExtensionHandler {
public:
    static BackupExtensionHandler* GetInstance();

    ErrCode OnBackup(MessageParcel &data, MessageParcel &reply);

private:
    BackupExtensionHandler() = default;
    ~BackupExtensionHandler() = default;
    void CollectBackupAdmins(BackupPayload &payload);
    ErrCode PrepareBackupData(const BackupPayload &payload, std::vector<uint8_t> &packedData);
    ErrCode EnsureBackupDir();
    ErrCode WriteBackupData(const std::vector<uint8_t> &packedData, MessageParcel &reply, bool &fdWritten);
    void ReplyBackupResult(MessageParcel &reply, uint32_t errorCode, int32_t successCount);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_BACKUP_EXTENSION_HANDLER_H
