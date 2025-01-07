/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "disable_microphone_query.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string PARAM_EDM_MIC_DISABLE = "persist.edm.mic_disable";

std::string DisableMicrophoneQuery::GetPolicyName()
{
    return "disable_microphone";
}

std::string DisableMicrophoneQuery::GetPermission(IPlugin::PermissionType permissionType,
    const std::string &permissionTag)
{
    if (permissionType == IPlugin::PermissionType::BYOD_DEVICE_ADMIN) {
        return "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS";
    }
    return "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
}

ErrCode DisableMicrophoneQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return GetBoolSystemParamSuccess(reply, PARAM_EDM_MIC_DISABLE, false);
}
} // namespace EDM
} // namespace OHOS