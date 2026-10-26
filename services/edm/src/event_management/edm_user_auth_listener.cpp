/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "edm_user_auth_listener.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
void EdmUserAuthListener::OnAuthFailureCountChanged(int32_t userId, int32_t failCount)
{
    EDMLOGI("EdmUserAuthListener::OnAuthFailureCountChanged userId=%{public}d failCount=%{public}d",
        userId, failCount);
    if (userId < 0 || failCount < 0) {
        EDMLOGE("EdmUserAuthListener invalid userId=%{public}d failCount=%{public}d", userId, failCount);
        return;
    }
    EdmEventData edmData;
    edmData.eventId = EventId{static_cast<uint32_t>(ManagedEvent::ON_PASSWORD_FAILED)};
    edmData.userId = userId;
    edmData.passwordFailedCount = failCount;
    manager_.DispatchEvent(edmData);
}
} // namespace EDM
} // namespace OHOS
