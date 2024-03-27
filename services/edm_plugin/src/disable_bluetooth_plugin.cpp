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

#include "disable_bluetooth_plugin.h"

#include "bluetooth_def.h"
#include "bluetooth_errorcode.h"
#include "bluetooth_host.h"
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisableBluetoothPlugin::GetPlugin());
const std::string DisableBluetoothPlugin::PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";

void DisableBluetoothPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableBluetoothPlugin, bool>> ptr)
{
    EDMLOGI("DisableBluetoothPlugin InitPlugin...");
    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11,
        "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH"));
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS"));
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_BLUETOOTH, "disabled_bluetooth", config, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableBluetoothPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisableBluetoothPlugin::OnSetPolicy(bool &disable)
{
    std::string originalPara = system::GetParameter(PERSIST_BLUETOOTH_CONTROL, "false");
    std::string newPara = disable ? "true" : "false";
    bool setParaRet = system::SetParameter(PERSIST_BLUETOOTH_CONTROL, newPara);
    if (!setParaRet) {
        EDMLOGW("DisableBluetoothPlugin failed when set system para: %{public}d", disable);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    if (disable && Bluetooth::BluetoothHost::GetDefaultHost().IsBrEnabled()) {
        int ret = Bluetooth::BluetoothHost::GetDefaultHost().DisableBt();
        if (ret != Bluetooth::BT_NO_ERROR) {
            setParaRet = system::SetParameter(PERSIST_BLUETOOTH_CONTROL, originalPara);
            EDMLOGW("DisableBluetoothPlugin failed when disable bt: %{public}d, rollback: %{public}d", ret, setParaRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }

    EDMLOGI("DisableBluetoothPlugin set system para: %{public}d", disable);
    return ERR_OK;
}

ErrCode DisableBluetoothPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    bool paraValue = system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(paraValue);
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS
