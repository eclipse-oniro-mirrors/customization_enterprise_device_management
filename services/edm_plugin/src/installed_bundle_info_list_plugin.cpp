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

#include "installed_bundle_info_list_plugin.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(InstalledBundleInfoListPlugin::GetPlugin());

void InstalledBundleInfoListPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InstalledBundleInfoListPlugin, std::string>> ptr)
{
    EDMLOGI("InstalledBundleInfoListPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_BUNDLE_INFO_LIST, PolicyName::POLICY_INSTALLED_BUNDLE_INFO_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}
} // namespace EDM
} // namespace OHOS
