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

#include "set_usb_device_states_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "usb_device_control_utils.h"
#include "usb_device_info.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<SetUsbDeviceStatesPlugin>());

SetUsbDeviceStatesPlugin::SetUsbDeviceStatesPlugin()
{
    EDMLOGI("SetUsbDeviceStatesPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SET_USB_DEVICE_STATES;
    policyName_ = PolicyName::POLICY_SET_USB_DEVICE_STATES;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode SetUsbDeviceStatesPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("SetUsbDeviceStatesPlugin OnHandlePolicy");
    USBDeviceConfigInfo config;
    if (!USBDeviceConfigInfo::Unmarshalling(data, config)) {
        EDMLOGE("SetUsbDeviceStatesPlugin Unmarshalling USBDeviceConfigInfo failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    bool isEnable = data.ReadBool();
    if (config.hasConfigId != config.hasInterfaceId) {
        EDMLOGE("SetUsbDeviceStatesPlugin configId/interfaceId must both be set or both absent");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return UsbDeviceControlUtils::SetUsbDeviceStates(config, isEnable);
}

ErrCode SetUsbDeviceStatesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SetUsbDeviceStatesPlugin OnGetPolicy");
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
