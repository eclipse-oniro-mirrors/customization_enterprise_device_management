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

#include "restrictions_proxy.h"

#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<RestrictionsProxy> RestrictionsProxy::instance_ = nullptr;
std::once_flag RestrictionsProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<RestrictionsProxy> RestrictionsProxy::GetRestrictionsProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<RestrictionsProxy>();
        }
    });
    return instance_;
}

int32_t RestrictionsProxy::SetDisallowedPolicy(const AppExecFwk::ElementName &admin, bool disallow, int policyCode,
    std::string permissionTag)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, disallow, policyCode, permissionTag);
}

int32_t RestrictionsProxy::SetDisallowedPolicy(MessageParcel &data, uint32_t policyCode)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(data, policyCode);
}

int32_t RestrictionsProxy::GetDisallowedPolicy(AppExecFwk::ElementName *admin, int policyCode, bool &result,
    std::string permissionTag)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, policyCode, result, permissionTag);
}

int32_t RestrictionsProxy::GetDisallowedPolicy(MessageParcel &data, uint32_t policyCode, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(data, policyCode, result);
}

int32_t RestrictionsProxy::SetFingerprintAuthDisabled(const AppExecFwk::ElementName &admin, bool disallow)
{
    EDMLOGD("RestrictionsProxy::SetFingerprintAuthDisabled");
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::FINGERPRINT_AUTH);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    data.WriteBool(disallow);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t RestrictionsProxy::IsFingerprintAuthDisabled(AppExecFwk::ElementName *admin, bool &result)
{
    EDMLOGD("RestrictionsProxy::GetFingerprintAuthDisabled");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    if (admin != nullptr) {
        data.WriteInt32(HAS_ADMIN);
        data.WriteParcelable(admin);
    } else {
        data.WriteInt32(WITHOUT_ADMIN);
    }
    data.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::FINGERPRINT_AUTH, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t RestrictionsProxy::SetDisallowedPolicyForAccount(const AppExecFwk::ElementName &admin, bool disallow,
    uint32_t policyCode, std::string permissionTag, int32_t accountId)
{
    EDMLOGD("RestrictionsProxy::SetDisallowedPolicyForAccount");
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, policyCode);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(permissionTag);
    data.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
    data.WriteBool(disallow);
    data.WriteInt32(accountId);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t RestrictionsProxy::GetDisallowedPolicyForAccount(AppExecFwk::ElementName &admin, int policyCode, bool &result,
    std::string permissionTag, int32_t accountId)
{
    EDMLOGD("RestrictionsProxy::GetDisallowedPolicyForAccount");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(permissionTag);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
    data.WriteInt32(accountId);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(policyCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    reply.ReadInt32(ret);
    if (ret != ERR_OK) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t RestrictionsProxy::AddOrRemoveDisallowedListForAccount(const AppExecFwk::ElementName &admin,
    std::string feature, std::vector<std::string> &bundles, int32_t accountId, bool isAdd)
{
    EDMLOGD("RestrictionsProxy::AddOrRemoveDisallowedListForAccount called");
    MessageParcel data;
    std::uint32_t interfaceCode = 0;
    if (!GetDisallowedListInterfaceCode(feature, interfaceCode)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::uint32_t funcCode = 0;
    if (isAdd) {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, interfaceCode);
    } else {
        funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, interfaceCode);
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(accountId);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(bundles);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t RestrictionsProxy::GetDisallowedListForAccount(AppExecFwk::ElementName &admin, std::string feature,
    int32_t accountId, std::vector<std::string> &result)
{
    EDMLOGD("RestrictionsProxy::GetDisallowedListForAccount called");
    std::uint32_t interfaceCode = 0;
    if (!GetDisallowedListInterfaceCode(feature, interfaceCode)) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(accountId);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(interfaceCode, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&result);
    return ERR_OK;
}

bool RestrictionsProxy::GetDisallowedListInterfaceCode(std::string feature, std::uint32_t &interfaceCode)
{
    auto it = featureInterfaceMap_.find(feature);
    if (it != featureInterfaceMap_.end()) {
        interfaceCode = it->second;
        return true;
    }
    return false;
}

int32_t RestrictionsProxy::SetUserRestriction(const AppExecFwk::ElementName &admin, bool disallow, int policyCode)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, disallow, policyCode,
        WITHOUT_PERMISSION_TAG);
}
} // namespace EDM
} // namespace OHOS
