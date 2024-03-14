/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "device_settings_proxy.h"

#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<DeviceSettingsProxy> DeviceSettingsProxy::instance_ = nullptr;
std::mutex DeviceSettingsProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<DeviceSettingsProxy> DeviceSettingsProxy::GetDeviceSettingsProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<DeviceSettingsProxy> temp = std::make_shared<DeviceSettingsProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t DeviceSettingsProxy::SetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t value)
{
    EDMLOGD("DeviceSettingsProxy::SetScreenOffTime");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(value);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SCREEN_OFF_TIME);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceSettingsProxy::GetScreenOffTime(const AppExecFwk::ElementName &admin, int32_t &value)
{
    EDMLOGD("DeviceSettingsProxy::GetScreenOffTime");
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
    proxy->GetPolicy(EdmInterfaceCode::SCREEN_OFF_TIME, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadInt32(value);
    return ERR_OK;
}

int32_t DeviceSettingsProxy::InstallUserCertificate(const AppExecFwk::ElementName &admin,
    const std::vector<uint8_t> &certArray, std::string &alias, std::string &result, std::string &innerCodeMsg)
{
    EDMLOGD("DeviceSettingsProxy::InstallUserCertificate");
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_CERTIFICATE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUInt8Vector(certArray);
    data.WriteString(alias);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    EDMLOGI("DeviceSettingsProxy::InstallUserCertificate : %{public}d.", ret);
    if (ret == ERR_OK) {
        result = reply.ReadString();
    } else if (ret == EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED) {
        int32_t certRetCode = ERR_INVALID_VALUE;
        reply.ReadInt32(certRetCode);
        innerCodeMsg = std::to_string(certRetCode);
    }
    return ret;
}

int32_t DeviceSettingsProxy::UninstallUserCertificate(const AppExecFwk::ElementName &admin, const std::string &alias,
    std::string &innerCodeMsg)
{
    EDMLOGD("DeviceSettingsProxy::UninstallUserCertificate");
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::INSTALL_CERTIFICATE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(alias);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    if (ret == EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED) {
        int32_t certRetCode = ERR_INVALID_VALUE;
        reply.ReadInt32(certRetCode);
        innerCodeMsg = std::to_string(certRetCode);
    }
    return ret;
}

int32_t DeviceSettingsProxy::SetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
    const PowerPolicy &powerPolicy)
{
    EDMLOGD("DeviceSettingsProxy::SetPowerPolicy");
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUint32(static_cast<uint32_t>(powerScene));
    if (!powerPolicy.Marshalling(data)) {
        EDMLOGE("DeviceSettingsProxy::SetPowerPolicy Marshalling proxy fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t DeviceSettingsProxy::GetPowerPolicy(const AppExecFwk::ElementName &admin, const PowerScene &powerScene,
    PowerPolicy &powerPolicy)
{
    EDMLOGD("DeviceSettingsProxy::GetPowerPolicy");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteUint32(static_cast<uint32_t>(powerScene));
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::POWER_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("DeviceSettingsProxy:getPowerPolicy fail. %{public}d", ret);
        return ret;
    }
    if (!PowerPolicy::Unmarshalling(reply, powerPolicy)) {
        EDMLOGE("DeviceSettingsProxy::getPowerPolicy Unmarshalling power policy fail.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS