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

#include "security_manager_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<SecurityManagerProxy> SecurityManagerProxy::instance_ = nullptr;
std::once_flag SecurityManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<SecurityManagerProxy> SecurityManagerProxy::GetSecurityManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SecurityManagerProxy>();
        }
    });
    return instance_;
}

int32_t SecurityManagerProxy::GetSecurityPatchTag(MessageParcel &data, std::string &securityPatchTag)
{
    EDMLOGD("SecurityManagerProxy::GetSecurityPatchTag");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_SECURITY_PATCH_TAG, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(securityPatchTag);
    return ret;
}

int32_t SecurityManagerProxy::GetSecurityPatchTag(const AppExecFwk::ElementName &admin, std::string &securityPatchTag)
{
    EDMLOGD("SecurityManagerProxy::GetSecurityPatchTag");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_SECURITY_PATCH_TAG, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(securityPatchTag);
    return ret;
}

int32_t SecurityManagerProxy::GetDeviceEncryptionStatus(const AppExecFwk::ElementName &admin,
    DeviceEncryptionStatus &deviceEncryptionStatus)
{
    EDMLOGD("SecurityManagerProxy::GetDeviceEncryptionStatus");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(deviceEncryptionStatus.isEncrypted);
    return ERR_OK;
}

int32_t SecurityManagerProxy::GetDeviceEncryptionStatus(MessageParcel &data,
    DeviceEncryptionStatus &deviceEncryptionStatus)
{
    EDMLOGD("SecurityManagerProxy::GetDeviceEncryptionStatus");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(deviceEncryptionStatus.isEncrypted);
    return ERR_OK;
}

int32_t SecurityManagerProxy::SetPasswordPolicy(MessageParcel &data)
{
    EDMLOGD("SecurityManagerProxy::SetPasswordPolicy");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::PASSWORD_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SecurityManagerProxy::GetPasswordPolicy(PasswordPolicy &policy)
{
    EDMLOGD("SecurityManagerProxy::GetPasswordPolicy innerapi");
    return GetPasswordPolicy(nullptr, policy);
}

int32_t SecurityManagerProxy::GetPasswordPolicy(const AppExecFwk::ElementName &admin, PasswordPolicy &policy)
{
    EDMLOGD("SecurityManagerProxy::GetPasswordPolicy");
    return GetPasswordPolicy(&admin, policy);
}

int32_t SecurityManagerProxy::GetPasswordPolicy(const AppExecFwk::ElementName *admin, PasswordPolicy &policy)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    if (admin == nullptr) {
        data.WriteString(EdmConstants::PERMISSION_TAG_SYSTEM_API);
        data.WriteInt32(WITHOUT_ADMIN);
        data.WriteInt32(WITHOUT_ADMIN);
    } else {
        data.WriteString(WITHOUT_PERMISSION_TAG);
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
        data.WriteInt32(HAS_ADMIN);
    }
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::PASSWORD_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    policy.complexityReg = reply.ReadString();
    reply.ReadInt64(policy.validityPeriod);
    policy.additionalDescription = reply.ReadString();
    return ERR_OK;
}

int32_t SecurityManagerProxy::GetRootCheckStatus(const AppExecFwk::ElementName &admin, std::string &info)
{
    EDMLOGD("SecurityManagerProxy::GetRootCheckStatus");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::POLICY_CODE_END + 8);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(funcCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadString(info);
    return ERR_OK;
}

int32_t SecurityManagerProxy::SetAppClipboardPolicy(MessageParcel &data)
{
    EDMLOGD("SecurityManagerProxy::SetAppClipboardPolicy");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::CLIPBOARD_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SecurityManagerProxy::GetAppClipboardPolicy(MessageParcel &data, std::string &policy)
{
    EDMLOGD("SecurityManagerProxy::GetAppClipboardPolicy");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::CLIPBOARD_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    policy = reply.ReadString();
    return ERR_OK;
}

int32_t SecurityManagerProxy::SetWatermarkImage(const AppExecFwk::ElementName &admin,
    std::shared_ptr<WatermarkParam> param)
{
    EDMLOGD("SecurityManagerProxy::SetWatermarkImage");
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::WATERMARK_IMAGE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::SecurityManager::SET_SINGLE_WATERMARK_TYPE);
    data.WriteString(param->bundleName);
    data.WriteInt32(param->accountId);
    data.WriteInt32(param->width);
    data.WriteInt32(param->height);
    data.WriteInt32(param->size);
    data.WriteRawData(reinterpret_cast<const void*>(param->pixels), param->size);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SecurityManagerProxy::CancelWatermarkImage(MessageParcel &data)
{
    EDMLOGD("SecurityManagerProxy::CancelWatermarkImage");
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::WATERMARK_IMAGE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t SecurityManagerProxy::InstallUserCertificate(const AppExecFwk::ElementName &admin,
    const CertBlobCA &certblobCA, std::string &result, std::string &innerCodeMsg)
{
    EDMLOGD("SecurityManagerProxy::InstallUserCertificate");
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_CERTIFICATE);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteUInt8Vector(certblobCA.certArray);
    data.WriteString(certblobCA.alias);
    data.WriteInt32(certblobCA.accountId);
    ErrCode ret = EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data, reply);
    EDMLOGI("DeviceSettingsProxy::InstallUserCertificate : %{public}d.", ret);
    if (ret == ERR_OK) {
        result = reply.ReadString();
    } else if (ret == EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED) {
        innerCodeMsg = reply.ReadString();
    }
    return ret;
}

int32_t SecurityManagerProxy::GetUserCertificates(MessageParcel &data, std::vector<std::string> &uriList)
{
    EDMLOGD("SecurityManagerProxy::GetUserCertificates");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::INSTALL_CERTIFICATE, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret == ERR_OK) {
        reply.ReadStringVector(&uriList);
    }
    return ret;
}
} // namespace EDM
} // namespace OHOS
