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

#include "set_wall_paper_plugin.h"

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "wall_paper_param_serializer.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetWallPaperPlugin::GetPlugin());

void SetWallPaperPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetWallPaperPlugin, WallPaperParam>> ptr)
{
    ptr->InitAttribute(EdmInterfaceCode::SET_WALL_PAPER, PolicyName::POLICY_SET_WALL_PAPER,
        EdmPermission::PERMISSION_ENTERPRISE_SET_WALLPAPER, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(WallPaperParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetWallPaperPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetWallPaperPlugin::OnSetPolicy(WallPaperParam &data)
{
    EDMLOGD("SetWallPaperPlugin start set wall paper.");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
