/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ext_info_manager.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
std::vector<std::string> ExtInfoManager::GetAgCommonEventName()
{
    std::vector<std::string> agCommonEventName;
    MessageParcel reply;
    if (SUCCEEDED(GetExtInfo(ExtInfoType::AG_EVENT_AND_PERMISSION, reply))) {
        reply.ReadStringVector(&agCommonEventName);
    }
    return agCommonEventName;
}

std::string ExtInfoManager::GetAdminProvisioningInfo()
{
    MessageParcel reply;
    if (FAILED(GetExtInfo(ExtInfoType::ADMIN_PROVISIONING_INFO, reply))) {
        return "";
    }
    int32_t res = ERR_INVALID_VALUE;
    if (!reply.ReadInt32(res) || FAILED(res)) {
        EDMLOGE("ExtInfoManager::GetAdminProvisioningInfo failed, %{public}d", res);
        return "";
    }
    return reply.ReadString();
}

WantAgentInfo ExtInfoManager::GetWantAgentInfo()
{
    WantAgentInfo wantAgentInfo;
    MessageParcel reply;
    if (SUCCEEDED(GetExtInfo(ExtInfoType::SETTINGS_DEVICE_MANAGEMENT, reply))) {
        wantAgentInfo.bundleName = reply.ReadString();
        wantAgentInfo.abilityName = reply.ReadString();
        wantAgentInfo.uri = reply.ReadString();
    }
    return wantAgentInfo;
}

ErrCode ExtInfoManager::GetExtInfo(ExtInfoType extInfoType, MessageParcel &reply)
{
    uint32_t funcCode = POLICY_FUNC_CODE((uint32_t)FuncOperateType::GET, (uint32_t)EdmInterfaceCode::GET_EXT_INFO);
    MessageParcel data;
    data.WriteInt32(static_cast<int32_t>(extInfoType));
    return PluginManager::GetInstance()->GetPolicy(funcCode, "", data, reply, EdmConstants::DEFAULT_USER_ID);
}
} // namespace EDM
} // namespace OHOS
