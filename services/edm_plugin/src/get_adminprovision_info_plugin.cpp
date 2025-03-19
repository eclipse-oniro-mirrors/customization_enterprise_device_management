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
#include "get_adminprovision_info_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetAdminProvisionInfoPlugin>());

const char* const BUNDLE_NAME = "com.ohos.adminprovisioning";

GetAdminProvisionInfoPlugin::GetAdminProvisionInfoPlugin()
{
    policyCode_ = EdmInterfaceCode::GET_ADMINPROVISION_INFO;
    policyName_ = PolicyName::POLICY_GET_ADMINPROVISION_INFO;
}

ErrCode GetAdminProvisionInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetAdminProvisionInfoPlugin::OnGetPolicy");
    reply.WriteInt32(ERR_OK);
    reply.WriteString(BUNDLE_NAME);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS