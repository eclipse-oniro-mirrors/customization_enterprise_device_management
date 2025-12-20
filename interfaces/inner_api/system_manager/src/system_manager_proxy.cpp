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

#include "edm_log.h"
#include "func_code.h"
#include "update_policy_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<SystemManagerProxy> SystemManagerProxy::instance_ = nullptr;
std::once_flag SystemManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

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

int32_t SystemManagerProxy::GetKeyEventPolicys(const AppExecFwk::ElementName &admin,
    std::vector<KeyCustomization> &KeyCustomizations)
{
    EDMLOGI("SystemManagerProxy::GetKeyEventPolicys");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
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
} // namespace EDM
} // namespace OHOS
