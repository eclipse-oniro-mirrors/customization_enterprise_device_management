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

int32_t TelephonyManagerProxy::AddCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const std::string &callType, const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::AddCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(callType);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::CallPolicy::NUMBER_LIST_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteStringVector(numbers);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::RemoveCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const std::string &callType, const int32_t policyFlag, const std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::RemoveCallPolicyNumbers.");
    MessageParcel data;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteString(callType);
    data.WriteInt32(policyFlag);
    if (numbers.size() > EdmConstants::CallPolicy::NUMBER_LIST_MAX_SIZE) {
        return ERR_INVALID_VALUE;
    }
    data.WriteStringVector(numbers);
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::TELEPHONY_CALL_POLICY);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::GetCallPolicyNumbers(const AppExecFwk::ElementName &admin,
    const std::string &callType, const int32_t policyFlag, std::vector<std::string> &numbers)
{
    EDMLOGD("TelephonyManagerProxy::GetCallPolicyNumbers.");
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(callType);
    data.WriteInt32(policyFlag);

    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::TELEPHONY_CALL_POLICY, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGE("EnterpriseDeviceMgrProxy:GetCallPolicyNumbers fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&numbers);
    EDMLOGD("EnterpriseDeviceMgrProxy:GetCallPolicyNumbers success");
    return ERR_OK;
}

int32_t TelephonyManagerProxy::HangupCalling(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::HangupCalling.");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::HANG_UP_CALLING);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::ActiveSim(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::ActiveSim ");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t TelephonyManagerProxy::DeactiveSim(MessageParcel &data)
{
    EDMLOGD("TelephonyManagerProxy::DeactiveSim");
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_SIM);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}
} // namespace EDM
} // namespace OHOS
