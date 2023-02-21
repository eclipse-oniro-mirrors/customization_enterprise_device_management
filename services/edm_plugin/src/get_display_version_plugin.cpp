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

#include "get_display_version_plugin.h"
#include "parameter.h"
#include "policy_info.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetDisplayVersionPlugin::GetPlugin());

void GetDisplayVersionPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDisplayVersionPlugin, std::string>> ptr)
{
    EDMLOGD("GetDisplayVersionPlugin InitPlugin...");
    std::string policyName;
    POLICY_CODE_TO_NAME(GET_DISPLAY_VERSION, policyName);
    ptr->InitAttribute(GET_DISPLAY_VERSION, policyName, "ohos.permission.ENTERPRISE_GET_DEVICE_INFO",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDisplayVersionPlugin::OnGetPolicy(std::string &policyData, MessageParcel &reply)
{
    EDMLOGI("GetDisplayVersionPlugin OnGetPolicy.");
    std::string version = GetDisplayVersion();
    reply.WriteInt32(ERR_OK);
    reply.WriteString(version);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
