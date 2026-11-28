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

#include "admin_provisioning_proxy.h"

#include <chrono>
#include <utility>

#include "element_name.h"
#include "edm_log.h"
#include "edm_constants.h"
#include "ext_info_manager.h"
#include "extension_manager_client.h"
#include "external_manager_factory.h"
#include "iexternal_manager_factory.h"
#include "iremote_object.h"
#include "message_parcel.h"
#include "message_option.h"
#include "string_ex.h"
#include "want.h"

namespace OHOS {
namespace EDM {

namespace {
constexpr int32_t AP_CONNECT_TIMEOUT_MS = 10000; // 10s
constexpr int32_t AP_IPC_TIMEOUT_MS = 5000;
} // namespace

void ApConnectionCallback::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    EDMLOGI("ApConnectionCallback::OnAbilityConnectDone result=%{public}d", resultCode);
    std::lock_guard<std::mutex> lock(mutex_);
    remote_ = remoteObject;
    resultCode_ = resultCode;
    connected_ = true;
    cv_.notify_all();
}

void ApConnectionCallback::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    EDMLOGI("ApConnectionCallback::OnAbilityDisconnectDone result=%{public}d", resultCode);
}

sptr<IRemoteObject> ApConnectionCallback::WaitForRemote(int32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] { return connected_; })) {
        EDMLOGE("ApConnectionCallback: wait connect timeout");
        return nullptr;
    }
    return remote_;
}

AdminProvisioningProxy* AdminProvisioningProxy::GetInstance()
{
    static AdminProvisioningProxy instance;
    return &instance;
}

namespace {
int32_t GetCurrentUserId()
{
    auto factory = std::make_shared<ExternalManagerFactory>();
    auto osAccountMgr = factory->CreateOsAccountManager();
    if (osAccountMgr == nullptr) {
        EDMLOGE("GetCurrentUserId: create os account mgr failed");
        return EdmConstants::DEFAULT_USER_ID;
    }
    std::vector<int32_t> ids;
    ErrCode ret = osAccountMgr->QueryActiveOsAccountIds(ids);
    if (FAILED(ret) || ids.empty()) {
        EDMLOGE("GetCurrentUserId: query active ids failed");
        return EdmConstants::DEFAULT_USER_ID;
    }
    return ids.at(0);
}
} // namespace

bool AdminProvisioningProxy::VerifyApIdentity()
{
    std::string apBundleName = ExtInfoManager::GetInstance()->GetAdminProvisioningInfo();
    if (apBundleName.empty()) {
        EDMLOGE("VerifyApIdentity: get ap bundle name failed");
        return false;
    }
    int32_t userId = GetCurrentUserId();
    auto factory = std::make_shared<ExternalManagerFactory>();
    auto bundleMgr = factory->CreateBundleManager();
    if (bundleMgr == nullptr) {
        EDMLOGE("VerifyApIdentity: create bundle mgr failed");
        return false;
    }
    bool isSystemApp = false;
    ErrCode ret = bundleMgr->IsSystemApp(apBundleName, userId, isSystemApp);
    if (FAILED(ret)) {
        EDMLOGE("VerifyApIdentity: IsSystemApp failed, ret=%{public}d", ret);
        return false;
    }
    if (!isSystemApp) {
        EDMLOGE("VerifyApIdentity: %{public}s is not system app", apBundleName.c_str());
        return false;
    }
    return true;
}

ErrCode AdminProvisioningProxy::ConnectApExtensionAbility(sptr<ApConnectionCallback> &callback)
{
    std::string apBundleName = ExtInfoManager::GetInstance()->GetAdminProvisioningInfo();
    if (apBundleName.empty()) {
        EDMLOGE("ConnectApExtensionAbility: get ap bundle name failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    callback = new (std::nothrow) ApConnectionCallback();
    if (callback == nullptr) {
        EDMLOGE("ConnectApExtensionAbility: new callback failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    AAFwk::Want want;
    want.SetElementName(apBundleName, ADMIN_PROVISIONING_BACKUP_ABILITY_NAME);
    int32_t userId = GetCurrentUserId();
    ErrCode ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, callback, nullptr, userId);
    if (ret != ERR_OK) {
        EDMLOGE("ConnectApExtensionAbility: connect failed, ret=%{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}

void AdminProvisioningProxy::DisconnectApExtensionAbility(sptr<ApConnectionCallback> &callback)
{
    if (callback == nullptr) {
        return;
    }
    ErrCode ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(callback);
    if (ret != ERR_OK) {
        EDMLOGW("DisconnectApExtensionAbility: disconnect failed, ret=%{public}d", ret);
    }
}

bool AdminProvisioningProxy::PrepareDataParcel(const std::vector<uint8_t> &payload, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(IAdminBackupRestore::GetDescriptor())) {
        EDMLOGE("PrepareDataParcel: write descriptor failed");
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(payload.size()))) {
        EDMLOGE("PrepareDataParcel: write size failed");
        return false;
    }
    if (!payload.empty() && !data.WriteRawData(payload.data(), payload.size())) {
        EDMLOGE("PrepareDataParcel: write raw data failed");
        return false;
    }
    return true;
}

bool AdminProvisioningProxy::PrepareBackupSignParcel(const std::vector<uint8_t> &payload, MessageParcel &data)
{
    if (!data.WriteInterfaceToken(IAdminBackupRestore::GetDescriptor())) {
        EDMLOGE("PrepareBackupSignParcel: write descriptor failed");
        return false;
    }
    // AP side (ArkTS) reads the payload via readString(), which maps to ReadString16 (UTF-16).
    // C++ Parcel::WriteString is UTF-8 and is NOT compatible with ReadString16, so the payload
    // must be written with WriteString16 to match the ArkTS reader.
    std::string payloadJson(payload.begin(), payload.end());
    if (!data.WriteString16(Str8ToStr16(payloadJson))) {
        EDMLOGE("PrepareBackupSignParcel: write payload failed");
        return false;
    }
    return true;
}

ErrCode AdminProvisioningProxy::ReadPackedDataFromReply(MessageParcel &reply, std::vector<uint8_t> &outPackedData)
{
    int32_t packedSize = reply.ReadInt32();
    if (packedSize < 0) {
        EDMLOGE("ReadPackedDataFromReply: invalid packed size %{public}d", packedSize);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    outPackedData.clear();
    if (packedSize > 0) {
        const uint8_t *raw = static_cast<const uint8_t *>(reply.ReadRawData(packedSize));
        if (raw == nullptr) {
            EDMLOGE("ReadPackedDataFromReply: read packed data failed");
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        outPackedData.assign(raw, raw + packedSize);
    }
    return ERR_OK;
}

ErrCode AdminProvisioningProxy::ReadAdminsFromReply(MessageParcel &reply, std::vector<AdminBackupItem> &outAdmins)
{
    std::string payloadJson = Str16ToStr8(reply.ReadString16());
    if (payloadJson.empty()) {
        EDMLOGE("ReadAdminsFromReply: empty payload");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    BackupPayload payload;
    std::vector<uint8_t> payloadBytes(payloadJson.begin(), payloadJson.end());
    if (!AdminBackupDataCodec::GetInstance()->Deserialize(payloadBytes, payload)) {
        EDMLOGE("ReadAdminsFromReply: deserialize payload failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    outAdmins = std::move(payload.admins);
    return ERR_OK;
}

ErrCode AdminProvisioningProxy::BackupSign(const std::vector<uint8_t> &adminData, std::vector<uint8_t> &outPackedData)
{
    if (!VerifyApIdentity()) {
        EDMLOGE("BackupSign: verify ap identity failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    sptr<ApConnectionCallback> callback;
    ErrCode ret = ConnectApExtensionAbility(callback);
    if (FAILED(ret)) {
        return ret;
    }
    sptr<IRemoteObject> remote = callback->WaitForRemote(AP_CONNECT_TIMEOUT_MS);
    if (remote == nullptr) {
        EDMLOGE("BackupSign: wait remote timeout");
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    MessageParcel data;
    if (!PrepareBackupSignParcel(adminData, data)) {
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    option.SetWaitTime(AP_IPC_TIMEOUT_MS);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(AdminBackupRestoreCode::BACKUP_SIGN),
        data, reply, option);
    if (result != ERR_OK) {
        EDMLOGE("BackupSign: SendRequest failed, result=%{public}d", result);
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    ErrCode apRet = reply.ReadInt32();
    if (FAILED(apRet)) {
        EDMLOGE("BackupSign: AP return failed, apRet=%{public}d", apRet);
        DisconnectApExtensionAbility(callback);
        return apRet;
    }
    ErrCode readRet = ReadPackedDataFromReply(reply, outPackedData);
    if (FAILED(readRet)) {
        DisconnectApExtensionAbility(callback);
        return readRet;
    }
    DisconnectApExtensionAbility(callback);
    return ERR_OK;
}

ErrCode AdminProvisioningProxy::RestoreVerify(const std::vector<uint8_t> &packedData,
    std::vector<AdminBackupItem> &outAdmins)
{
    if (!VerifyApIdentity()) {
        EDMLOGE("RestoreVerify: verify ap identity failed");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    sptr<ApConnectionCallback> callback;
    ErrCode ret = ConnectApExtensionAbility(callback);
    if (FAILED(ret)) {
        return ret;
    }
    sptr<IRemoteObject> remote = callback->WaitForRemote(AP_CONNECT_TIMEOUT_MS);
    if (remote == nullptr) {
        EDMLOGE("RestoreVerify: wait remote timeout");
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    MessageParcel data;
    if (!PrepareDataParcel(packedData, data)) {
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    option.SetWaitTime(AP_IPC_TIMEOUT_MS);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(AdminBackupRestoreCode::RESTORE_VERIFY),
        data, reply, option);
    if (result != ERR_OK) {
        DisconnectApExtensionAbility(callback);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    ErrCode apRet = reply.ReadInt32();
    if (FAILED(apRet)) {
        EDMLOGE("RestoreVerify: AP return failed, apRet=%{public}d", apRet);
        DisconnectApExtensionAbility(callback);
        return apRet;
    }
    ErrCode readRet = ReadAdminsFromReply(reply, outAdmins);
    if (FAILED(readRet)) {
        DisconnectApExtensionAbility(callback);
        return readRet;
    }
    DisconnectApExtensionAbility(callback);
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS
