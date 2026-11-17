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

#include <cstdint>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "usb_policy_utils.h"
#include "usb_srv_client.h"

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
    if (!UsbPolicyUtils::IsUsbInterceptEnabled()) {
        EDMLOGE("SetUsbDeviceStatesPlugin USB dynamic control is not enabled");
        return EdmReturnErrCode::USB_DYNAMIC_CONTROL_NOT_ENABLED;
    }
    return SetUsbDeviceStates(config, isEnable);
}

ErrCode SetUsbDeviceStatesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SetUsbDeviceStatesPlugin OnGetPolicy");
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

bool SetUsbDeviceStatesPlugin::IsInterfaceAuthorize(const USBDeviceConfigInfo &config)
{
    return config.hasConfigId && config.hasInterfaceId;
}

ErrCode SetUsbDeviceStatesPlugin::MapUsbRet(int32_t usbRet, const char *apiName)
{
    if (usbRet == static_cast<int32_t>(EdmReturnErrCode::INTERFACE_UNSUPPORTED)) {
        EDMLOGW("SetUsbDeviceStatesPlugin %{public}s: parameter verification failed", apiName);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (usbRet == EdmConstants::USB_ERRCODE_INTERFACE_NO_INIT) {
        EDMLOGW("SetUsbDeviceStatesPlugin %{public}s: USB interface not init", apiName);
        return ERR_OK;
    }
    if (usbRet != ERR_OK) {
        EDMLOGE("SetUsbDeviceStatesPlugin %{public}s failed, ret=%{public}d", apiName, usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode SetUsbDeviceStatesPlugin::SetUsbDeviceStates(const USBDeviceConfigInfo &config, bool isEnable)
{
    if (config.busNum < 0 || config.devAddress < 0 ||
        config.busNum > static_cast<int32_t>(UINT8_MAX) ||
        config.devAddress > static_cast<int32_t>(UINT8_MAX)) {
        EDMLOGE("SetUsbDeviceStatesPlugin busNum/devAddress out of uint8 range");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    uint8_t busNum = static_cast<uint8_t>(config.busNum);
    uint8_t devAddr = static_cast<uint8_t>(config.devAddress);
    auto &usbClient = USB::UsbSrvClient::GetInstance();
    if (IsInterfaceAuthorize(config)) {
        if (config.configId < 0 || config.interfaceId < 0 ||
            config.configId > static_cast<int32_t>(UINT8_MAX) ||
            config.interfaceId > static_cast<int32_t>(UINT8_MAX)) {
            EDMLOGE("SetUsbDeviceStatesPlugin config/interface id out of range");
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
        int32_t usbRet = usbClient.UsbInterfaceAuthorize(busNum, devAddr,
            static_cast<uint8_t>(config.configId), static_cast<uint8_t>(config.interfaceId), isEnable);
        return MapUsbRet(usbRet, "UsbInterfaceAuthorize");
    }
    int32_t usbRet = usbClient.UsbDeviceAuthorize(busNum, devAddr, isEnable);
    return MapUsbRet(usbRet, "UsbDeviceAuthorize");
}
} // namespace EDM
} // namespace OHOS
