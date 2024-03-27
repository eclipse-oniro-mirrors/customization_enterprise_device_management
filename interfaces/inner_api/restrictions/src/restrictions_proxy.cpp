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
} // namespace EDM
} // namespace OHOS
