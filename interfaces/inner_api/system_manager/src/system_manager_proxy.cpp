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
std::mutex SystemManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<SystemManagerProxy> SystemManagerProxy::GetSystemManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<SystemManagerProxy> temp = std::make_shared<SystemManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t SystemManagerProxy::SetNTPServer(const AppExecFwk::ElementName &admin, const std::string &value)
{
    EDMLOGD("SystemManagerProxy::SetNTPServer");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(value);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::NTP_SERVER);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SystemManagerProxy::GetNTPServer(const AppExecFwk::ElementName &admin, std::string &value)
{
    EDMLOGD("SystemManagerProxy::GetNTPServer");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
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

int32_t SystemManagerProxy::SetOTAUpdatePolicy(const AppExecFwk::ElementName &admin, const UpdatePolicy &updatePolicy,
    std::string &errorMsg)
{
    EDMLOGD("SystemManagerProxy::SetOTAUpdatePolicy");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    UpdatePolicyUtils::WriteUpdatePolicy(data, updatePolicy);
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_OTA_UPDATE_POLICY);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::PARAM_ERROR) {
        errorMsg = reply.ReadString();
    }
    return ret;
}

int32_t SystemManagerProxy::GetOTAUpdatePolicy(const AppExecFwk::ElementName &admin, UpdatePolicy &updatePolicy)
{
    EDMLOGD("SystemManagerProxy::GetOTAUpdatePolicy");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
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
    const UpgradePackageInfo &packageInfo, std::string &errMsg)
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
    UpdatePolicyUtils::ClosePackagesFileHandle(packageInfo.packages);
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
} // namespace EDM
} // namespace OHOS
