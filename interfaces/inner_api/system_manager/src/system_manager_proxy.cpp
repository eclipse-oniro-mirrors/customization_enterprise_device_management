/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "system_manager_proxy.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_utils.h"
#include "func_code.h"
#include "message_parcel.h"
#include "print_policy_util.h"
#include "update_policy_utils.h"
#include "want.h"

namespace OHOS {
namespace EDM {
#ifndef FEATURE_PC_ONLY
namespace {
class EdmSaDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    EdmSaDeathRecipient() = default;
    ~EdmSaDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &) override
    {
        EDMLOGI("EdmSaDeathRecipient::OnRemoteDied edm SA died, clear client timer callbacks");
        auto proxy = SystemManagerProxy::GetSystemManagerProxy();
        if (proxy == nullptr) {
            return;
        }
        auto cb = proxy->GetClientTimerCallback();
        if (cb != nullptr) {
            cb->ClearAll();
        }
    }
};
}
#endif

std::shared_ptr<SystemManagerProxy> SystemManagerProxy::instance_ = nullptr;
std::once_flag SystemManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

SystemManagerProxy::SystemManagerProxy()
{
#ifndef FEATURE_PC_ONLY
    clientCallback_ = new (std::nothrow) EdmClientTimerCallback();
    edmDeathRecipient_ = new (std::nothrow) EdmSaDeathRecipient();
#endif
}

std::shared_ptr<SystemManagerProxy> SystemManagerProxy::GetSystemManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SystemManagerProxy>();
        }
    });
    return instance_;
}

int32_t SystemManagerProxy::SetNTPServer(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetNTPServer");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::NTP_SERVER);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetNTPServer(MessageParcel &data, std::string &value)
{
    EDMLOGD("SystemManagerProxy::GetNTPServer");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::NTP_SERVER, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(value);
    return ERR_OK;
}

#if defined(FEATURE_PC_ONLY)
int32_t SystemManagerProxy::SetOtaUpdateNonceEnable(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetOtaUpdateNonceEnable");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::OTA_UPDATE_NONCE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
 
int32_t SystemManagerProxy::IsOtaUpdateNonceEnable(MessageParcel &data, bool &isOtaNonceEnable)
{
    EDMLOGD("SystemManagerProxy::IsOtaUpdateNonceEnable");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::OTA_UPDATE_NONCE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(isOtaNonceEnable);
    return ERR_OK;
}

int32_t SystemManagerProxy::AddOrRemoveAllowedPrinterIPAddresses(MessageParcel &data, FuncOperateType operateType)
{
    EDMLOGD("SystemManagerProxy::AddOrRemoveAllowedPrinterIPAddresses");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
 
int32_t SystemManagerProxy::GetAllowedPrinterIPAddresses(MessageParcel &data, std::vector<std::string> &ipAddresses)
{
    EDMLOGD("SystemManagerProxy::GetAllowedPrinterIPAddresses");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&ipAddresses);
    return ERR_OK;
}
 
int32_t SystemManagerProxy::AddOrRemoveAllowedPrinterIPAddressesForAccount(MessageParcel &data,
    FuncOperateType operateType)
{
    EDMLOGD("SystemManagerProxy::AddOrRemoveAllowedPrinterIPAddressesForAccount");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
 
int32_t SystemManagerProxy::GetAllowedPrinterIPAddressesForAccount(MessageParcel &data,
    std::vector<std::string> &ipAddresses)
{
    EDMLOGD("SystemManagerProxy::GetAllowedPrinterIPAddresses");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&ipAddresses);
    return ERR_OK;
}
 
ErrCode SystemManagerProxy::GetPrintPolicy(const std::string userId, std::string &json)
{
    EDMLOGI("SystemManagerProxy::GetPrintPolicy userId=%{public}s", userId.c_str());
    int32_t userIdInt = 0;
    if (EdmUtils::ParseStringToInt(userId, userIdInt) != ERR_OK) {
        EDMLOGE("SystemManagerProxy::GetPrintPolicy invalid userId");
        json = "{}";
        return ERR_OK;
    }
    return PrintPolicyUtil::GetPrintPolicy(userIdInt, json);
}
#endif

int32_t SystemManagerProxy::SetOTAUpdatePolicy(MessageParcel &data, std::string &errorMsg)
{
    EDMLOGD("SystemManagerProxy::SetOTAUpdatePolicy");
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_OTA_UPDATE_POLICY);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::PARAM_ERROR) {
        errorMsg = reply.ReadString();
    }
    return ret;
}

int32_t SystemManagerProxy::GetOTAUpdatePolicy(MessageParcel &data, UpdatePolicy &updatePolicy)
{
    EDMLOGD("SystemManagerProxy::GetOTAUpdatePolicy");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::SET_OTA_UPDATE_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    UpdatePolicyUtils::ReadUpdatePolicy(reply, updatePolicy);
    return ERR_OK;
}

int32_t SystemManagerProxy::NotifyUpdatePackages(const AppExecFwk::ElementName &admin,
    UpgradePackageInfo &packageInfo, std::string &errMsg)
{
    EDMLOGD("SystemManagerProxy::NotifyUpdatePackages");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    UpdatePolicyUtils::WriteUpgradePackageInfo(data, packageInfo);
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::UPGRADE_PACKAGES_ANALYZE_FAILED) {
        errMsg = reply.ReadString();
    }
    return ret;
}

int32_t SystemManagerProxy::GetUpgradeResult(const AppExecFwk::ElementName &admin, const std::string &version,
    UpgradeResult &upgradeResult)
{
    EDMLOGD("SystemManagerProxy::GetUpgradeResult");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteInt32(static_cast<int32_t>(GetUpdateInfo::UPDATE_RESULT));
    data.WriteString(version);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    UpdatePolicyUtils::ReadUpgradeResult(reply, upgradeResult);
    return ERR_OK;
}

int32_t SystemManagerProxy::GetUpdateAuthData(MessageParcel &data, std::string &authData)
{
    EDMLOGD("SystemManagerProxy::GetUpdateAuthData.");
    MessageParcel reply;
    data.WriteInt32(static_cast<int32_t>(GetUpdateInfo::UPDATE_AUTH_DATA));
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(authData);
    return ERR_OK;
}

int32_t SystemManagerProxy::SetAutoUnlockAfterReboot(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetAutoUnlockAfterReboot");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetAutoUnlockAfterReboot(MessageParcel &data, bool &authData)
{
    EDMLOGD("SystemManagerProxy::GetAutoUnlockAfterReboot");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(authData);
    return ERR_OK;
}

int32_t SystemManagerProxy::SetInstallLocalEnterpriseAppEnabled(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetInstallLocalEnterpriseAppEnabled");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
 
int32_t SystemManagerProxy::GetInstallLocalEnterpriseAppEnabled(MessageParcel &data, bool &isAllowedInstall)
{
    EDMLOGD("SystemManagerProxy::GetInstallLocalEnterpriseAppEnabled");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(isAllowedInstall);
    return ERR_OK;
}

#if defined(FEATURE_PC_ONLY)
int32_t SystemManagerProxy::SetInstallLocalEnterpriseAppEnabledForAccount(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetInstallLocalEnterpriseAppEnabledForAccount");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetInstallLocalEnterpriseAppEnabledForAccount(MessageParcel &data, bool &isAllowedInstall)
{
    EDMLOGD("SystemManagerProxy::GetInstallLocalEnterpriseAppEnabledForAccount");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(isAllowedInstall);
    return ERR_OK;
}
#endif

int32_t SystemManagerProxy::AddOrRemoveDisallowedNearlinkProtocols(MessageParcel &data, FuncOperateType operateType)
{
    EDMLOGD("SystemManagerProxy::AddOrRemoveDisallowedNearlinkProtocols");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::DISALLOWED_NEARLINK_PROTOCOLS);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetDisallowedNearlinkProtocols(MessageParcel &data, std::vector<int32_t> &protocols)
{
    EDMLOGD("SystemManagerProxy::GetDisallowedNearlinkProtocols");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DISALLOWED_NEARLINK_PROTOCOLS, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("SystemManagerProxy:GetDisallowedNearlinkProtocols fail. %{public}d", ret);
        return ret;
    }
    if (!reply.ReadInt32Vector(&protocols)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

#if defined(FEATURE_PC_ONLY) && defined(LOG_SERVICE_PLUGIN_EDM_ENABLE)
int32_t SystemManagerProxy::StartCollectlog(const AppExecFwk::ElementName &admin)
{
    EDMLOGD("SystemManagerProxy::StartCollectlog");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::FinishLogCollected(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::CollectApplicationFaultlog");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
#endif

int32_t SystemManagerProxy::SetKeyEventPolicys(const AppExecFwk::ElementName &admin,
    const std::vector<KeyCustomization> &KeyCustomizations, std::string &retMessage)
{
    EDMLOGI("SystemManagerProxy::SetKeyEventPolicys");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_KEY_CODE_POLICYS);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    KeyEventHandle::WriteKeyCustomizationVector(data, KeyCustomizations);
    ErrCode ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret != ERR_OK) {
        retMessage = reply.ReadString();
        return ret;
    }
    return ERR_OK;
}

int32_t SystemManagerProxy::RemoveKeyEventPolicys(const AppExecFwk::ElementName &admin,
    const std::vector<int32_t> &KeyCodes)
{
    EDMLOGI("SystemManagerProxy::RemoveKeyEventPolicys");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::SET_KEY_CODE_POLICYS);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32Vector(KeyCodes);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetKeyEventPolicies(MessageParcel &data, std::vector<KeyCustomization> &KeyCustomizations)
{
    EDMLOGI("SystemManagerProxy::GetKeyEventPolicies with MessageParcel");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::SET_KEY_CODE_POLICYS, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy::GetPolicy fail. %{public}d", ret);
        return ret;
    }
    KeyEventHandle::ReadKeyCustomizationVector(reply, KeyCustomizations);
    return ERR_OK;
}

int32_t SystemManagerProxy::SetActivationLockDisabled(const AppExecFwk::ElementName &admin,
    bool &isDisabled, const std::string &credential)
{
    EDMLOGD("SystemManagerProxy::SetActivationLockDisabled");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteBool(isDisabled);
    data.WriteString(credential);
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISABLED_ACTIVATION_LOCK);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
    return ret;
}

int32_t SystemManagerProxy::IsActivationLockDisabled(AppExecFwk::ElementName &admin, bool &result)
{
    EDMLOGD("SystemManagerProxy::IsActivationLockDisabled");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DISABLED_ACTIVATION_LOCK,
        data, reply);
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        EDMLOGD("SystemManagerProxy::GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t SystemManagerProxy::SetLocalHotaDomain(MessageParcel &data)
{
    EDMLOGD("SystemManagerProxy::SetLocalHotaDomain");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::LOCAL_HOTA_DOMAIN);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetLocalHotaDomain(MessageParcel &data, std::string &domain)
{
    EDMLOGD("SystemManagerProxy::GetLocalHotaDomain");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel reply;
    proxy->GetPolicy(EdmInterfaceCode::LOCAL_HOTA_DOMAIN, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("SystemManagerProxy::GetLocalHotaDomain fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(domain);
    return ERR_OK;
}

#ifndef FEATURE_PC_ONLY
sptr<EdmClientTimerCallback> SystemManagerProxy::GetClientTimerCallback()
{
    return clientCallback_;
}

void SystemManagerProxy::EnsureEdmSaDeathRecipient()
{
    if (edmDeathRecipient_ == nullptr) {
        EDMLOGE("SystemManagerProxy::EnsureEdmSaDeathRecipient deathRecipient is null");
        return;
    }
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> remote = proxy->GetEdmRemoteObject();
    if (remote == nullptr) {
        EDMLOGW("SystemManagerProxy::EnsureEdmSaDeathRecipient edm remote is null");
        return;
    }
    std::lock_guard<std::mutex> lock(drMutex_);
    if (registeredRemote_ != nullptr && registeredRemote_.GetRefPtr() == remote.GetRefPtr()) {
        return;
    }
    if (registeredRemote_ != nullptr) {
        registeredRemote_->RemoveDeathRecipient(edmDeathRecipient_);
    }
    remote->AddDeathRecipient(edmDeathRecipient_);
    registeredRemote_ = remote;
    EDMLOGI("SystemManagerProxy::EnsureEdmSaDeathRecipient registered on new remote");
}
#endif

#ifndef FEATURE_PC_ONLY
int32_t SystemManagerProxy::CreateTimer(const AppExecFwk::ElementName &admin, bool repeat,
    uint64_t interval, const std::string &name, uint64_t &timerId)
{
    EDMLOGI("SystemManagerProxy::CreateTimer");
    EnsureEdmSaDeathRecipient();
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::CREATE));
    data.WriteBool(repeat);
    data.WriteUint64(interval);
    data.WriteString(name);
    if (clientCallback_ != nullptr) {
        data.WriteRemoteObject(clientCallback_->AsObject());
    } else {
        EDMLOGE("SystemManagerProxy::CreateTimer clientCallback is null");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
    MessageParcel reply;
    int32_t ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret != ERR_OK) {
        EDMLOGE("SystemManagerProxy::CreateTimer failed ret=%{public}d", ret);
        return ret;
    }
    timerId = reply.ReadUint64();
    return ERR_OK;
}

int32_t SystemManagerProxy::StartTimer(const AppExecFwk::ElementName &admin, uint64_t timerId, uint64_t triggerTime)
{
    EDMLOGI("SystemManagerProxy::StartTimer");
    EnsureEdmSaDeathRecipient();
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::START));
    data.WriteUint64(timerId);
    data.WriteUint64(triggerTime);
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
    MessageParcel reply;
    return proxy->HandleDevicePolicy(funcCode, data, reply);
}

int32_t SystemManagerProxy::StopTimer(const AppExecFwk::ElementName &admin, uint64_t timerId)
{
    EDMLOGI("SystemManagerProxy::StopTimer");
    EnsureEdmSaDeathRecipient();
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::STOP));
    data.WriteUint64(timerId);
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
    MessageParcel reply;
    return proxy->HandleDevicePolicy(funcCode, data, reply);
}

int32_t SystemManagerProxy::DestroyTimer(const AppExecFwk::ElementName &admin, uint64_t timerId)
{
    EDMLOGI("SystemManagerProxy::DestroyTimer");
    EnsureEdmSaDeathRecipient();
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(static_cast<int32_t>(TimerOperationType::DESTROY));
    data.WriteUint64(timerId);
    uint32_t funcCode = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET),
        EdmInterfaceCode::SYSTEM_TIMER_OPERATION);
    MessageParcel reply;
    int32_t ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret == ERR_OK && clientCallback_ != nullptr) {
        clientCallback_->RemoveCallback(timerId);
    }
    return ret;
}
#endif
} // namespace EDM
} // namespace OHOS
