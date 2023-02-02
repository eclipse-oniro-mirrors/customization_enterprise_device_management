/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "edm_data_ability_utils.h"
#include "get_device_name_plugin.h"
#include "parameter.h"
#include "policy_info.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const std::string PREDICATES_STRING = "settings.general.device_name";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetDeviceNamePlugin::GetPlugin());

void GetDeviceNamePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDeviceNamePlugin, std::string>> ptr)
{
    EDMLOGD("GetDeviceNamePlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(GET_DEVICE_NAME, policyName);
    ptr->InitAttribute(GET_DEVICE_NAME, policyName, "ohos.permission.ENTERPRISE_GET_DEVICE_INFO", false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDeviceNamePlugin::OnGetPolicy(std::string &policyData, MessageParcel &reply)
{
    EDMLOGI("GetDeviceNamePlugin OnGetPolicy GetMarketName");
    std::string name;
    ErrCode code = EdmDataAbilityUtils::GetStringFromDataShare(SETTINGS_DATA_BASE_URI, PREDICATES_STRING, name);
    if (code != ERR_OK) {
        EDMLOGD("GetDeviceNamePlugin::get device name from database failed : %{public}d.", code);
        reply.WriteInt32(code);
        return code;
    }
    if (name.empty()) {
        name = GetMarketName();
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(name);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
