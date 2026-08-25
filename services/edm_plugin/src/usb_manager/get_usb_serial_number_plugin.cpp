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

#include "get_usb_serial_number_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "usb_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetUsbSerialNumberPlugin>());

GetUsbSerialNumberPlugin::GetUsbSerialNumberPlugin()
{
    EDMLOGI("GetUsbSerialNumberPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_USB_SERIAL_NUMBER;
    policyName_ = PolicyName::POLICY_USB_SERIAL_NUMBER;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetUsbSerialNumberPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetUsbSerialNumberPlugin OnGetPolicy.");
    int32_t busNum = data.ReadInt32();
    int32_t devAddress = data.ReadInt32();
    std::string serial;
    ErrCode ret = UsbPolicyUtils::GetUsbSerialNumber(busNum, devAddress, serial);
    reply.WriteInt32(ret);
    if (ret == ERR_OK) {
        reply.WriteString(serial);
    }
    return ret;
}
} // namespace EDM
} // namespace OHOS