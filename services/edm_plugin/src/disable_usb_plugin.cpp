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

#include "disable_usb_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "usb_srv_client.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(DisableUsbPlugin::GetPlugin());

void DisableUsbPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableUsbPlugin, bool>> ptr)
{
    EDMLOGI("DisableUsbPlugin InitPlugin...");
    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11,
        "ohos.permission.ENTERPRISE_MANAGE_USB"));
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS"));
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_USB, "disable_usb", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableUsbPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableUsbPlugin::OnAdminRemove);
}

ErrCode DisableUsbPlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("DisableUsbPlugin OnSetPolicy...disable = %{public}d", data);
    auto policyManager = IPolicyManager::GetInstance();
    std::string allowUsbDevicePolicy;
    policyManager->GetPolicy("", "allowed_usb_devices", allowUsbDevicePolicy);
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", "usb_read_only", usbStoragePolicy);
    if (data && (!allowUsbDevicePolicy.empty() ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED) ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY))) {
        EDMLOGE("DisableUsbPlugin OnSetPolicy: CONFLICT! allowedUsbDevice: %{public}s, usbStoragePolicy: %{public}s",
            allowUsbDevicePolicy.c_str(), usbStoragePolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageGlobalInterface(data);
    if (usbRet != ERR_OK) {
        EDMLOGE("DisableUsbPlugin OnSetPolicy: ManageGlobalInterface failed! ret:%{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisableUsbPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisableUsbPlugin OnGetPolicy %{public}s...", policyData.c_str());
    bool isDisabled = false;
    pluginInstance_->serializer_->Deserialize(policyData, isDisabled);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisabled);
    return ERR_OK;
}

ErrCode DisableUsbPlugin::OnAdminRemove(const std::string &adminName, bool &data, int32_t userId)
{
    EDMLOGI("DisableUsbPlugin OnAdminRemove %{public}d...", data);
    if (!data) {
        return ERR_OK;
    }
    auto &srvClient = OHOS::USB::UsbSrvClient::GetInstance();
    int32_t usbRet = srvClient.ManageGlobalInterface(!data);
    if (usbRet != ERR_OK) {
        EDMLOGE("DisableUsbPlugin OnSetPolicy: ManageGlobalInterface failed! ret:%{public}d", usbRet);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
