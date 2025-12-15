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

#include "ui_ability_controller.h"

#include "ability_manager_client.h"
#include "edm_log.h"
#include "ipc_skeleton.h"
#include "permission_checker.h"

namespace OHOS {
namespace EDM {
ErrCode UIAbilityController::StartAbilityByAdmin(const AAFwk::Want &want, const sptr<IRemoteObject> &token,
    int32_t userId)
{
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, token, userId);
    if (FAILED(ret)) {
        EDMLOGE("UIAbilityController::StartAbilityByAdmin fail ret: %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool UIAbilityController::VerifyPermission(const std::string &callerName)
{
    if (callerName == abilityInfo_.bundleName) {
        return true;
    }

    if (!abilityInfo_.visible) {
        return false;
    }

    if (abilityInfo_.permissions.empty()) {
        return true;
    }

    // 校验UIAbility保护权限
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    for (const auto &permission : abilityInfo_.permissions) {
        if (!PermissionChecker::GetInstance()->VerifyCallingPermission(tokenId, permission)) {
            EDMLOGE("VerifyPermission: %{public}s DENIED", permission.c_str());
            return false;
        }
    }
    return true;
}
} // namespace EDM
} // namespace OHOS