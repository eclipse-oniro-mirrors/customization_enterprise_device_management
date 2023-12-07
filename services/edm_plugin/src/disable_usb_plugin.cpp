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
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "usb_srv_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableUsbPlugin::GetPlugin());

void DisableUsbPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableUsbPlugin, bool>> ptr)
{
    EDMLOGD("DisableUsbPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_USB, "disable_usb",
        "ohos.permission.ENTERPRISE_MANAGE_USB", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableUsbPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableUsbPlugin::OnAdminRemove);
}

ErrCode DisableUsbPlugin::OnSetPolicy(bool &data)
{
    EDMLOGI("DisableUsbPlugin OnSetPolicy...disable = %{public}d", data);
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
