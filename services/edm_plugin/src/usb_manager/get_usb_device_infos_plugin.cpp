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

#include "get_usb_device_infos_plugin.h"

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
    std::make_shared<GetUsbDeviceInfosPlugin>());

GetUsbDeviceInfosPlugin::GetUsbDeviceInfosPlugin()
{
    EDMLOGI("GetUsbDeviceInfosPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_USB_DEVICE_INFOS;
    policyName_ = PolicyName::POLICY_USB_DEVICE_INFOS;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetUsbDeviceInfosPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetUsbDeviceInfosPlugin OnGetPolicy.");
    std::vector<UsbDeviceInfo> deviceInfos;
    ErrCode ret = UsbDeviceControlUtils::GetUsbDeviceInfos(deviceInfos);
    if (ret != ERR_OK) {
        EDMLOGE("GetUsbDeviceInfosPlugin GetUsbDeviceInfos failed, ret=%{public}d", ret);
        reply.WriteInt32(ret);
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(static_cast<uint32_t>(deviceInfos.size()));
    for (const auto &deviceInfo : deviceInfos) {
        if (!deviceInfo.Marshalling(reply)) {
            EDMLOGE("GetUsbDeviceInfosPlugin Marshalling failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
