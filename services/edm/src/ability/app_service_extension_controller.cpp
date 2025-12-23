/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "app_service_extension_controller.h"

#include "ability_manager_client.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
ErrCode AppServiceExtensionController::StartAbilityByAdmin(const AAFwk::Want &want, int32_t userId)
{
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartExtensionAbility(want, nullptr, userId,
        AppExecFwk::ExtensionAbilityType::APP_SERVICE);
    if (FAILED(ret)) {
        EDMLOGE("AppServiceExtensionController::StartAbilityByAdmin fail ret: %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool AppServiceExtensionController::VerifyPermission(const std::string &callerName)
{
    if (callerName == abilityInfo_.bundleName) {
        return true;
    }

    return abilityInfo_.visible;
}
} // namespace EDM
} // namespace OHOS