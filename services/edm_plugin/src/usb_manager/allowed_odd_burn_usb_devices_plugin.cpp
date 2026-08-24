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

#include "allowed_odd_burn_usb_devices_plugin.h"

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "odd_burn_usb_device.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(AllowedOddBurnUsbDevicesPlugin::GetPlugin());

void AllowedOddBurnUsbDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<AllowedOddBurnUsbDevicesPlugin, std::vector<OddBurnUsbDevice>>> ptr)
{
    EDMLOGI("AllowedOddBurnUsbDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::ALLOWED_ODD_BURN_USB_DEVICES,
        PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayOddBurnUsbDeviceSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&AllowedOddBurnUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&AllowedOddBurnUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&AllowedOddBurnUsbDevicesPlugin::OnAdminRemove);
}

ErrCode AllowedOddBurnUsbDevicesPlugin::OnSetPolicy(std::vector<OddBurnUsbDevice> &data,
    std::vector<OddBurnUsbDevice> &currentData, std::vector<OddBurnUsbDevice> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedOddBurnUsbDevicesPlugin OnSetPolicy");
    if (data.empty()) {
        EDMLOGW("AllowedOddBurnUsbDevicesPlugin OnSetPolicy data is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (data.size() > EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("AllowedOddBurnUsbDevicesPlugin OnSetPolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::vector<OddBurnUsbDevice> afterHandle =
        ArrayOddBurnUsbDeviceSerializer::GetInstance()->SetUnionPolicyData(currentData, data);
    std::vector<OddBurnUsbDevice> afterMerge =
        ArrayOddBurnUsbDeviceSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);

    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode AllowedOddBurnUsbDevicesPlugin::OnRemovePolicy(std::vector<OddBurnUsbDevice> &data,
    std::vector<OddBurnUsbDevice> &currentData, std::vector<OddBurnUsbDevice> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedOddBurnUsbDevicesPlugin OnRemovePolicy");
    if (data.empty()) {
        EDMLOGW("AllowedOddBurnUsbDevicesPlugin OnRemovePolicy data is empty");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (data.size() > EdmConstants::ALLOWED_ODD_BURN_USB_DEVICES_MAX_SIZE) {
        EDMLOGE("AllowedOddBurnUsbDevicesPlugin OnRemovePolicy data size=[%{public}zu] is too large", data.size());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::vector<OddBurnUsbDevice> afterHandle =
        ArrayOddBurnUsbDeviceSerializer::GetInstance()->SetDifferencePolicyData(data, currentData);
    std::vector<OddBurnUsbDevice> afterMerge =
        ArrayOddBurnUsbDeviceSerializer::GetInstance()->SetUnionPolicyData(mergeData, afterHandle);

    currentData = afterHandle;
    mergeData = afterMerge;
    return ERR_OK;
}

ErrCode AllowedOddBurnUsbDevicesPlugin::OnAdminRemove(const std::string &adminName,
    std::vector<OddBurnUsbDevice> &data, std::vector<OddBurnUsbDevice> &mergeData, int32_t userId)
{
    EDMLOGI("AllowedOddBurnUsbDevicesPlugin OnAdminRemove");
    if (data.empty()) {
        return ERR_OK;
    }
    std::vector<OddBurnUsbDevice> needRemoveMergePolicy =
        ArrayOddBurnUsbDeviceSerializer::GetInstance()->SetDifferencePolicyData(mergeData, data);
    mergeData = needRemoveMergePolicy;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
