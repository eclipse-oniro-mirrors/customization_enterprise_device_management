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

#include "set_datetime_plugin.h"

#include "edm_ipc_interface_code.h"
#include "long_serializer.h"
#include "time_service_client.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetDateTimePlugin::GetPlugin());

void SetDateTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDateTimePlugin, int64_t>> ptr)
{
    EDMLOGI("SetDateTimePlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_DATETIME, "set_datetime", config, false);
    ptr->SetSerializer(LongSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDateTimePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDateTimePlugin::OnSetPolicy(int64_t &data)
{
    EDMLOGD("SetDateTimePlugin OnSetPolicy");
    MiscServices::TimeServiceClient::GetInstance()->SetTime(data);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
