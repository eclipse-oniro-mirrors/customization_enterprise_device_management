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

#include "conflict_group_registry.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

ConflictGroupRegistry& ConflictGroupRegistry::GetInstance()
{
    static ConflictGroupRegistry instance;
    return instance;
}

ConflictGroupRegistry::ConflictGroupRegistry()
{
    RegisterConflictGroupUsb();
    RegisterConflictGroupBluetooth();
    RegisterConflictGroupSudo();
    RegisterConflictGroupNotification();
    RegisterConflictGroupDistribute();
    RegisterConflictGroupMTP();
    RegisterConflictGroupWifi();
    RegisterConflictGroupPrinter();
    RegisterConflictGroupRunningBundles();
    RegisterConflictGroupResetFactory();
    RegisterConflictGroupSuperHub();
    RegisterConflictGroupUpdatePolicy();
}

void ConflictGroupRegistry::RegisterConflictGroupUsb()
{
    // Group A: USB policies (7 policies, bidirectional + one-directional)
    policyToGroup_[EdmInterfaceCode::DISABLE_USB] = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::ALLOWED_USB_DEVICES] = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::USB_READ_ONLY] = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_USB_DEVICES] = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::DISALLOW_USB_SERIAL] = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE] =
        static_cast<int32_t>(ConflictGroupId::GROUP_USB);
}

void ConflictGroupRegistry::RegisterConflictGroupBluetooth()
{
    // Group B: Bluetooth device lists (3 policies)
    policyToGroup_[EdmInterfaceCode::DISABLE_BLUETOOTH] = static_cast<int32_t>(ConflictGroupId::GROUP_BLUETOOTH);
    policyToGroup_[EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_BLUETOOTH);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_BLUETOOTH);
}

void ConflictGroupRegistry::RegisterConflictGroupSudo()
{
    // Group C: Sudo (2 policies)
    policyToGroup_[EdmInterfaceCode::DISALLOWED_SUDO] = static_cast<int32_t>(ConflictGroupId::GROUP_SUDO);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_DEVICE_SUDO] = static_cast<int32_t>(ConflictGroupId::GROUP_SUDO);
}

void ConflictGroupRegistry::RegisterConflictGroupNotification()
{
    // Group D: Notification (2 policies)
    policyToGroup_[EdmInterfaceCode::DISALLOWED_NOTIFICATION] =
        static_cast<int32_t>(ConflictGroupId::GROUP_NOTIFICATION);
    policyToGroup_[EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_NOTIFICATION);
}

void ConflictGroupRegistry::RegisterConflictGroupDistribute()
{
    // Group E: Distributed transmission (2 policies)
    policyToGroup_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION] =
        static_cast<int32_t>(ConflictGroupId::GROUP_DISTRIBUTED);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL] =
        static_cast<int32_t>(ConflictGroupId::GROUP_DISTRIBUTED);
}

void ConflictGroupRegistry::RegisterConflictGroupMTP()
{
    // Group F: MTP client (2 policies, device-level vs user-level)
    policyToGroup_[EdmInterfaceCode::DISABLE_MTP_CLIENT] = static_cast<int32_t>(ConflictGroupId::GROUP_MTP);
    policyToGroup_[EdmInterfaceCode::DISABLE_USER_MTP_CLIENT] = static_cast<int32_t>(ConflictGroupId::GROUP_MTP);
}

void ConflictGroupRegistry::RegisterConflictGroupWifi()
{
    // Group G: WiFi lists (3 policies)
    policyToGroup_[EdmInterfaceCode::DISABLE_WIFI] = static_cast<int32_t>(ConflictGroupId::GROUP_WIFI);
    policyToGroup_[EdmInterfaceCode::ALLOWED_WIFI_LIST] = static_cast<int32_t>(ConflictGroupId::GROUP_WIFI);
    policyToGroup_[EdmInterfaceCode::DISALLOWED_WIFI_LIST] = static_cast<int32_t>(ConflictGroupId::GROUP_WIFI);
}

void ConflictGroupRegistry::RegisterConflictGroupPrinter()
{
    // Group H: Printer IP addresses (2 policies, device-level vs user-level)
    policyToGroup_[EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE] =
        static_cast<int32_t>(ConflictGroupId::GROUP_PRINTER);
    policyToGroup_[EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT] =
        static_cast<int32_t>(ConflictGroupId::GROUP_PRINTER);
}

void ConflictGroupRegistry::RegisterConflictGroupRunningBundles()
{
    // Group I: Running bundles (3 policies)
    policyToGroup_[EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_RUNNING_BUNDLES);
    policyToGroup_[EdmInterfaceCode::ALLOW_RUNNING_BUNDLES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_RUNNING_BUNDLES);
    policyToGroup_[EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS] =
        static_cast<int32_t>(ConflictGroupId::GROUP_RUNNING_BUNDLES);
}

void ConflictGroupRegistry::RegisterConflictGroupResetFactory()
{
    // Group J: Factory reset / secure erase (4 policies, one-directional guards)
    policyToGroup_[EdmInterfaceCode::OPERATE_DEVICE] = static_cast<int32_t>(ConflictGroupId::GROUP_FACTORY_RESET);
    policyToGroup_[EdmInterfaceCode::RESET_FACTORY] = static_cast<int32_t>(ConflictGroupId::GROUP_FACTORY_RESET);
    policyToGroup_[EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_RESET_FACTORY] =
        static_cast<int32_t>(ConflictGroupId::GROUP_FACTORY_RESET);
    policyToGroup_[EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_SECURE_ERASE] =
        static_cast<int32_t>(ConflictGroupId::GROUP_FACTORY_RESET);
}

void ConflictGroupRegistry::RegisterConflictGroupSuperHub()
{
    // Group K: SuperHub (3 policies, one-directional guard)
    policyToGroup_[EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS] =
        static_cast<int32_t>(ConflictGroupId::GROUP_SUPERHUB);
    policyToGroup_[EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_SUPERHUB] =
        static_cast<int32_t>(ConflictGroupId::GROUP_SUPERHUB);
    policyToGroup_[EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::HIDDEN_SETTINGS_MENU] =
        static_cast<int32_t>(ConflictGroupId::GROUP_SUPERHUB);
}

void ConflictGroupRegistry::RegisterConflictGroupUpdatePolicy()
{
    // Group L: UpdatePolicy (2 policies, one-directional guard)
    policyToGroup_[EdmInterfaceCode::SET_OTA_UPDATE_POLICY] =
        static_cast<int32_t>(ConflictGroupId::GROUP_UPDATE_POLICY);
    policyToGroup_[EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES] =
        static_cast<int32_t>(ConflictGroupId::GROUP_UPDATE_POLICY);
}

int32_t ConflictGroupRegistry::GetConflictGroupId(uint32_t policyCode) const
{
    auto it = policyToGroup_.find(policyCode);
    if (it != policyToGroup_.end()) {
        return it->second;
    }
    return static_cast<int32_t>(ConflictGroupId::NONE);
}
} // namespace EDM
} // namespace OHOS
