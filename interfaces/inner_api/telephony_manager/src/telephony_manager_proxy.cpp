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
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(data, EdmInterfaceCode::DISALLOWED_SIM, result);
}

} // namespace EDM
} // namespace OHOS
