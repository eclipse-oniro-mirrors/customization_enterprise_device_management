/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "enterprise_device_mgr_proxy.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EnterpriseDeviceMgrProxy> EnterpriseDeviceMgrProxy::instance_ = nullptr;

std::shared_ptr<EnterpriseDeviceMgrProxy> EnterpriseDeviceMgrProxy::GetInstance()
{
    return instance_;
}

ErrCode EnterpriseDeviceMgrProxy::EnableAdmin(AppExecFwk::ElementName& admin, EntInfo& entInfo, AdminType type,
    int32_t userId)
{
    if (admin.GetAbilityName() == "xxx") {
        return EdmReturnErrCode::COMPONENT_INVALID;
    }
    if (admin.GetBundleName() == "super.bundle" && admin.GetAbilityName() == "super.ability") {
        return ERR_OK;
    }
    if (admin.GetBundleName() == "byod.bundle" && admin.GetAbilityName() == "byod.ability") {
        return ERR_OK;
    }
    if (admin.GetBundleName() == "da.bundle" && admin.GetAbilityName() == "da.ability") {
        return ERR_OK;
    }
    return ERR_OK;
}

ErrCode EnterpriseDeviceMgrProxy::DisableAdmin(AppExecFwk::ElementName& admin, int32_t userId)
{
    if (admin.GetBundleName() == "xxx") {
        return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
    }
    if (admin.GetBundleName() == "super.bundle") {
        return ERR_OK;
    }
    if (admin.GetBundleName() == "byod.bundle") {
        return ERR_OK;
    }
    if (admin.GetBundleName() == "da.bundle") {
        return ERR_OK;
    }
    return EdmReturnErrCode::DISABLE_ADMIN_FAILED;
}
} // namespace EDM
} // namespace OHOS