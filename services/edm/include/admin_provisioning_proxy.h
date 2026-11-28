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

#ifndef SERVICES_EDM_INCLUDE_ADMIN_PROVISIONING_PROXY_H
#define SERVICES_EDM_INCLUDE_ADMIN_PROVISIONING_PROXY_H

#include <cstdint>
#include <string>
#include <vector>

#include "ability_connect_callback_stub.h"
#include "edm_errors.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"

#include "admin_backup_data_codec.h"

namespace OHOS {
namespace EDM {

constexpr const char* ADMIN_PROVISIONING_BACKUP_ABILITY_NAME = "BackupSignExtensionAbility";

enum class AdminBackupRestoreCode : uint32_t {
    BACKUP_SIGN = 1,
    RESTORE_VERIFY = 2,
};

class IAdminBackupRestore : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.edm.IAdminBackupRestore");
    virtual ErrCode BackupSign(const std::vector<uint8_t> &adminData, std::vector<uint8_t> &outPackedData) = 0;
    virtual ErrCode RestoreVerify(const std::vector<uint8_t> &packedData,
        std::vector<AdminBackupItem> &outAdmins) = 0;
};

class ApConnectionCallback : public AAFwk::AbilityConnectionStub {
public:
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;
    sptr<IRemoteObject> WaitForRemote(int32_t timeoutMs);
    void SetResultCode(int32_t code) { resultCode_ = code; }
    int32_t GetResultCode() const { return resultCode_; }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    sptr<IRemoteObject> remote_;
    int32_t resultCode_ = -1;
    bool connected_ = false;
};

class AdminProvisioningProxy {
public:
    static AdminProvisioningProxy* GetInstance();

    bool VerifyApIdentity();
    ErrCode BackupSign(const std::vector<uint8_t> &adminData, std::vector<uint8_t> &outPackedData);
    ErrCode RestoreVerify(const std::vector<uint8_t> &packedData, std::vector<AdminBackupItem> &outAdmins);

private:
    AdminProvisioningProxy() = default;
    ~AdminProvisioningProxy() = default;
    ErrCode ConnectApExtensionAbility(sptr<ApConnectionCallback> &callback);
    void DisconnectApExtensionAbility(sptr<ApConnectionCallback> &callback);
    bool PrepareDataParcel(const std::vector<uint8_t> &payload, MessageParcel &data);
    bool PrepareBackupSignParcel(const std::vector<uint8_t> &payload, MessageParcel &data);
    ErrCode ReadPackedDataFromReply(MessageParcel &reply, std::vector<uint8_t> &outPackedData);
    ErrCode ReadAdminsFromReply(MessageParcel &reply, std::vector<AdminBackupItem> &outAdmins);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_ADMIN_PROVISIONING_PROXY_H
