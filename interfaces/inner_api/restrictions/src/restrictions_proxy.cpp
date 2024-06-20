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
std::mutex RestrictionsProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<RestrictionsProxy> RestrictionsProxy::GetRestrictionsProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<RestrictionsProxy> temp = std::make_shared<RestrictionsProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t RestrictionsProxy::SetDisallowedPolicy(const AppExecFwk::ElementName &admin, bool disallow, int policyCode,
    std::string permissionTag)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, disallow, policyCode, permissionTag);
}

int32_t RestrictionsProxy::GetDisallowedPolicy(AppExecFwk::ElementName *admin, int policyCode, bool &result,
    std::string permissionTag)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, policyCode, result, permissionTag);
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
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(admin);
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
    int policyCode, std::string permissionTag, int32_t accountId)
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
} // namespace EDM
} // namespace OHOS
