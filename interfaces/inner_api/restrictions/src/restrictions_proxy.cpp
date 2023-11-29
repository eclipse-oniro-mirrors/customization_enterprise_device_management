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

int32_t RestrictionsProxy::SetPrinterDisabled(const AppExecFwk::ElementName &admin, bool isDisabled)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, isDisabled,
        EdmInterfaceCode::DISABLED_PRINTER);
}

int32_t RestrictionsProxy::SetHdcDisabled(const AppExecFwk::ElementName &admin, bool isDisabled)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, isDisabled,
        EdmInterfaceCode::DISABLED_HDC);
}

int32_t RestrictionsProxy::IsPrinterDisabled(AppExecFwk::ElementName *admin, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLED_PRINTER, result);
}

int32_t RestrictionsProxy::IsHdcDisabled(AppExecFwk::ElementName *admin, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISABLED_HDC, result);
}

int32_t RestrictionsProxy::DisallowScreenShot(const AppExecFwk::ElementName &admin, bool isDisabled)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, isDisabled,
        EdmInterfaceCode::DISALLOW_SCREEN_SHOT);
}

int32_t RestrictionsProxy::IsScreenShotDisallowed(AppExecFwk::ElementName *admin, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISALLOW_SCREEN_SHOT,
        result);
}

int32_t RestrictionsProxy::DisallowMicrophone(const AppExecFwk::ElementName &admin, bool isDisabled)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->SetPolicyDisabled(admin, isDisabled,
        EdmInterfaceCode::DISALLOW_MICROPHONE);
}

int32_t RestrictionsProxy::IsMicrophoneDisallowed(AppExecFwk::ElementName *admin, bool &result)
{
    return EnterpriseDeviceMgrProxy::GetInstance()->IsPolicyDisabled(admin, EdmInterfaceCode::DISALLOW_MICROPHONE,
        result);
}
} // namespace EDM
} // namespace OHOS
