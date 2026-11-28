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

#ifndef SERVICES_EDM_INCLUDE_RESTORE_EXTENSION_HANDLER_H
#define SERVICES_EDM_INCLUDE_RESTORE_EXTENSION_HANDLER_H

#include <string>

#include "admin_backup_data_codec.h"
#include "edm_errors.h"
#include "message_parcel.h"

namespace OHOS {
namespace EDM {

class RestoreExtensionHandler {
public:
    static RestoreExtensionHandler* GetInstance();

    ErrCode OnRestore(MessageParcel &data, MessageParcel &reply);

private:
    RestoreExtensionHandler() = default;
    ~RestoreExtensionHandler() = default;

    bool IsEnterpriseDevice();
    bool ValidateRestoreDevice(RestoreSummary &summary);
    bool ReadAndVerify(int32_t fd, std::vector<AdminBackupItem> &admins, RestoreSummary &summary);
    bool CheckExistingAdmin(const AdminBackupItem &item, RestoreItem &outResult);
    bool CheckCapacityConstraints(const AdminBackupItem &item, RestoreItem &outResult);
    RestoreItem RestoreOneAdmin(const AdminBackupItem &item);
    ErrCode EnableAdminFromBackup(const AdminBackupItem &item);
    void WriteResult(MessageParcel &reply, const RestoreSummary &summary);
    void WriteResult(MessageParcel &reply, uint32_t errorCode, const std::string &errorInfo);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_RESTORE_EXTENSION_HANDLER_H
