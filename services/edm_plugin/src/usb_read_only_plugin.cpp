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

#include "int_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "usb_srv_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(UsbReadOnlyPlugin::GetPlugin());
constexpr int32_t READ_ONLY = 1;
constexpr int32_t DISABLED = 2;

void UsbReadOnlyPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<UsbReadOnlyPlugin, int32_t>> ptr)
{
    EDMLOGD("UsbReadOnlyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::USB_READ_ONLY, "usb_read_only", "ohos.permission.ENTERPRISE_MANAGE_USB",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&UsbReadOnlyPlugin::SetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&UsbReadOnlyPlugin::OnAdminRemove);
}

ErrCode UsbReadOnlyPlugin::SetPolicy(int32_t &policyValue)
{
    EDMLOGI("UsbReadOnlyPlugin SetPolicy: %{public}d", policyValue);
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    if (policyValue == DISABLED) {
        int32_t usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, true);
        if (usbRet != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin SetPolicy: ManageInterfaceType failed! ret:%{public}d", usbRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    std::string usbKey = "persist.filemanagement.usb.readonly";
    std::string usbValue = (policyValue == READ_ONLY) ? "true" : "false";
    bool ret = OHOS::system::SetParameter(usbKey, usbValue);
    int32_t usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, false);
    EDMLOGI("UsbReadOnlyPlugin SetPolicy sysParam: readonly value:%{public}s  ret:%{public}d usbRet:%{public}d",
        usbValue.c_str(), ret, usbRet);
    return (ret && usbRet == ERR_OK) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode UsbReadOnlyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("UsbReadOnlyPlugin OnGetPolicy: %{public}s", policyData.c_str());
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(std::stoi(policyData));
    return ERR_OK;
}

ErrCode UsbReadOnlyPlugin::OnAdminRemove(const std::string &adminName, int32_t &data, int32_t userId)
{
    EDMLOGI("UsbReadOnlyPlugin OnAdminRemove adminName: %{public}s, userId: %{public}d, value: %{public}d",
        adminName.c_str(), userId, data);
    if (data == DISABLED) {
        auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
        int32_t usbRet = srvClient.ManageInterfaceType(OHOS::USB::InterfaceType::TYPE_STORAGE, false);
        if (usbRet != ERR_OK) {
            EDMLOGE("UsbReadOnlyPlugin OnAdminRemove: ManageInterfaceType failed! ret:%{public}d", usbRet);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    std::string usbKey = "persist.filemanagement.usb.readonly";
    std::string usbValue = "false";
    bool ret = OHOS::system::SetParameter(usbKey, usbValue);
    return ret ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
