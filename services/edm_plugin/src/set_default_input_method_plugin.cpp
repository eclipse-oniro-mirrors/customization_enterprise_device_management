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

#include "set_default_input_method_plugin.h"

#include "edm_ipc_interface_code.h"
#include "input_method_controller.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetDefaultInputMethodPlugin::GetPlugin());

void SetDefaultInputMethodPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDefaultInputMethodPlugin,
    std::string>> ptr)
{
    EDMLOGD("SetDefaultInputMethodPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_DEFAULT_INPUT_METHOD, PolicyName::POLICY_SET_DEFAULT_INPUT_METHOD,
        config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDefaultInputMethodPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDefaultInputMethodPlugin::OnSetPolicy(std::string &data)
{
    EDMLOGD("SetDefaultInputMethodPlugin OnSetPolicy data %{public}s.", data.c_str());
    auto imeController = MiscServices::InputMethodController::GetInstance();
    std::vector<MiscServices::Property> properties;
    imeController->ListInputMethod(properties);
    auto item = std::find_if(properties.begin(), properties.end(), [data] (MiscServices::Property property) {
        return property.name == data;
    });
    if (item == properties.end()) {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    int32_t ret = imeController->EnableIme(data);
    if (ret != ERR_OK) {
        EDMLOGE("SetDefaultInputMethodPlugin enable ime failed : %{public}d.", ret);
    }
    ret = imeController->SwitchInputMethod(MiscServices::SwitchTrigger::NATIVE_SA, data);
    if (ret != ERR_OK) {
        EDMLOGE("SetDefaultInputMethodPlugin set default input failed : %{public}d.", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
