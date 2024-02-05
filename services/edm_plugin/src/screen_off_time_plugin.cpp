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

#include "screen_off_time_plugin.h"

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "int_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
static constexpr int32_t SCREEN_OFF_TIME_MIN_VALUE = 15000;
static constexpr int32_t SCREEN_OFF_TIME_NEVER_VALUE = -1;

const std::string KEY_SCREEN_OFF_TIME = "settings.display.screen_off_timeout";

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(ScreenOffTimePlugin::GetPlugin());

void ScreenOffTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ScreenOffTimePlugin, int32_t>> ptr)
{
    EDMLOGI("ScreenOffTimePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SCREEN_OFF_TIME, "screen_off_time", false);
    ptr->InitPermission(FuncOperateType::SET, "ohos.permission.ENTERPRISE_SET_SCREENOFF_TIME",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->InitPermission(FuncOperateType::GET, "ohos.permission.ENTERPRISE_GET_SETTINGS",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ScreenOffTimePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ScreenOffTimePlugin::OnSetPolicy(int32_t &data)
{
    EDMLOGD("ScreenOffTimePlugin start set screen off time value = %{public}d.", data);
    if (data >= SCREEN_OFF_TIME_MIN_VALUE || data == SCREEN_OFF_TIME_NEVER_VALUE) {
        ErrCode code =
            EdmDataAbilityUtils::UpdateSettingsData(KEY_SCREEN_OFF_TIME, std::to_string(data));
        if (FAILED(code)) {
            EDMLOGE("ScreenOffTimePlugin::set screen off time failed : %{public}d.", code);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    return EdmReturnErrCode::PARAM_ERROR;
}

ErrCode ScreenOffTimePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ScreenOffTimePlugin OnGetPolicy");
    int32_t result = 0;
    ErrCode code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(KEY_SCREEN_OFF_TIME, result);
    if (code != ERR_OK) {
        EDMLOGE("ScreenOffTimePlugin::get screen off time from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
