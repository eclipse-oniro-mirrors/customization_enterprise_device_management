/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "usb_policy_utils.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableUsbPlugin::GetPlugin());

void DisableUsbPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableUsbPlugin, bool>> ptr)
{
    EDMLOGI("DisableUsbPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_USB, PolicyName::POLICY_DISABLE_USB, config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableUsbPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableUsbPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&DisableUsbPlugin::OnOtherServiceStart);
}

ErrCode DisableUsbPlugin::SetOtherModulePolicy(bool data)
{
    EDMLOGI("DisableUsbPlugin OnSetPolicy...disable = %{public}d", data);
    if (data && HasConflictPolicy()) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (FAILED(UsbPolicyUtils::SetUsbDisabled(data))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool DisableUsbPlugin::HasConflictPolicy()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! allowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return true;
    }
    std::string disallowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_DEVICES, disallowUsbDevice);
    if (!disallowUsbDevice.empty()) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! disallowUsbDevice: %{public}s", disallowUsbDevice.c_str());
        return true;
    }
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY, usbStoragePolicy);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED) ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY)) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! usbStoragePolicy: %{public}s", usbStoragePolicy.c_str());
        return true;
    }
    return false;
}

ErrCode DisableUsbPlugin::RemoveOtherModulePolicy()
{
    return UsbPolicyUtils::SetUsbDisabled(true);
}

void DisableUsbPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("DisableUsbPlugin::OnOtherServiceStart start");
    std::string disableUsbPolicy;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISABLE_USB,
        disableUsbPolicy, EdmConstants::DEFAULT_USER_ID);
    bool isUsbDisabled = false;
    BoolSerializer::GetInstance()->Deserialize(disableUsbPolicy, isUsbDisabled);
    if (isUsbDisabled) {
        ErrCode disableUsbRet = UsbPolicyUtils::SetUsbDisabled(isUsbDisabled);
        if (disableUsbRet != ERR_OK) {
            EDMLOGW("SetUsbDisabled Error: %{public}d", disableUsbRet);
        }
    }
}
} // namespace EDM
} // namespace OHOS
