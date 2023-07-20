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

#include "usb_read_only_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(UsbReadOnlyPlugin::GetPlugin());

void UsbReadOnlyPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<UsbReadOnlyPlugin, bool>> ptr)
{
    EDMLOGD("UsbReadOnlyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::USB_READ_ONLY, "usb_read_only", "ohos.permission.ENTERPRISE_MANAGE_USB",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&UsbReadOnlyPlugin::SetPolicy, FuncOperateType::SET);
}

ErrCode UsbReadOnlyPlugin::SetPolicy(bool &policyValue)
{
    EDMLOGD("UsbReadOnlyPlugin SetPolicy");
    std::string usbKey = "persist.filemanagement.usb.readonly";
    std::string usbValue = policyValue ? "true" : "false";
    bool ret = OHOS::system::SetParameter(usbKey, usbValue);
    EDMLOGD("UsbReadOnlyPlugin SetPolicy persist.filemanagement.usb.readonly value:%{public}s ret:%{public}d",
        usbValue.c_str(), ret);
    return ret ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
