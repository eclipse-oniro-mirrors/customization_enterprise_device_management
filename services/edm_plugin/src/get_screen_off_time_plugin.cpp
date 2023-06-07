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

#include "get_screen_off_time_plugin.h"

#include "edm_data_ability_utils.h"
#include "int_serializer.h"
#include "policy_info.h"

namespace OHOS {
namespace EDM {
const std::string PREDICATES_STRING = "settings.display.screen_off_timeout";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetScreenOffTimePlugin::GetPlugin());

void GetScreenOffTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetScreenOffTimePlugin, int32_t>> ptr)
{
    EDMLOGD("GetScreenOffTimePlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(SCREEN_OFF_TIME, policyName);
    ptr->InitAttribute(SCREEN_OFF_TIME, policyName, "ohos.permission.ENTERPRISE_GET_SETTINGS",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
}

ErrCode GetScreenOffTimePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetScreenOffTimePlugin OnGetPolicy");
    int32_t result = 0;
    ErrCode code = EdmDataAbilityUtils::GetIntFromDataShare(EdmDataAbilityUtils::SETTINGS_DATA_BASE_URI,
        PREDICATES_STRING, result);
    if (code != ERR_OK) {
        EDMLOGE("GetScreenOffTimePlugin::get screen off time from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
