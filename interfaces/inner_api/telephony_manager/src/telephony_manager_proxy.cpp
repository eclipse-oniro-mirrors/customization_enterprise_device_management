/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "telephony_manager_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<TelephonyManagerProxy> TelephonyManagerProxy::instance_ = nullptr;
std::once_flag TelephonyManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

TelephonyManagerProxy::TelephonyManagerProxy() {}

TelephonyManagerProxy::~TelephonyManagerProxy() {}

std::shared_ptr<TelephonyManagerProxy> TelephonyManagerProxy::GetTelephonyManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<TelephonyManagerProxy>();
        }
    });
    return instance_;
}

int32_t TelephonyManagerProxy::SetSimDisabled(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::SetSimDisabled.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::SetSimEnabled(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::SetSimEnabled.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::IsSimDisabled(MessageParcel &data, bool &result)
{
    EDMLOGD("TelephonyManagerProxy::IsSimDisabled");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DISALLOWED_SIM, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool isSuccess = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!isSuccess) {
        EDMLOGE("IsSimDisabled:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(result);
    return ERR_OK;
}

int32_t TelephonyManagerProxy::AddOutgoingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::AddOutgoingCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::CallPolicy::OUTGOING);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteInt32(numbers.size());
    for (const auto& iter : numbers) {
        data.WriteString(iter);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DOMAIN_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::RemoveOutgoingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::RemoveOutgoingCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::CallPolicy::OUTGOING);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteInt32(numbers.size());
    for (const auto& iter : numbers) {
        data.WriteString(iter);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DOMAIN_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::GetOutgoingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::GetOutgoingCallPolicyNumbers.");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(EdmConstants::CallPolicy::OUTGOING);
    data.WriteInt32(policyFlag);

    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DOMAIN_CALL_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetOutgoingCallPolicyNumbers fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetOutgoingCallPolicyNumbers size overlimit. size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string number = reply.ReadString();
        numbers.push_back(number);
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:GetOutgoingCallPolicyNumbers success. %{public}d", size);
    return ERR_OK;
}

int32_t TelephonyManagerProxy::AddIncomingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::AddIncomingCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::CallPolicy::INCOMING);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteInt32(numbers.size());
    for (const auto& iter : numbers) {
        data.WriteString(iter);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DOMAIN_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::RemoveIncomingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::RemoveIncomingCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(EdmConstants::CallPolicy::INCOMING);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteInt32(numbers.size());
    for (const auto& iter : numbers) {
        data.WriteString(iter);
    }
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DOMAIN_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::GetIncomingCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const int32_t policyFlag, std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::GetIncomingCallPolicyNumbers.");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(EdmConstants::CallPolicy::INCOMING);
    data.WriteInt32(policyFlag);

    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::DOMAIN_CALL_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetIncomingCallPolicyNumbers fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetIncomingCallPolicyNumbers size overlimit. size: %{public}d", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (int32_t i = 0; i < size; i++) {
        std::string number = reply.ReadString();
        numbers.push_back(number);
    }
    EDMLOGD("EnterpriseDeviceMgrProxy:GetIncomingCallPolicyNumbers success. %{public}d", size);
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS
