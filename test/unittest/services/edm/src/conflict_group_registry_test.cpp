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

#include <gtest/gtest.h>
#include "conflict_group_registry.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {

class ConflictGroupRegistryTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(ConflictGroupRegistryTest, TestGetInstance, TestSize.Level1)
{
    auto &instance1 = ConflictGroupRegistry::GetInstance();
    auto &instance2 = ConflictGroupRegistry::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdUsbGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_USB);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_USB), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_USB_DEVICES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::USB_READ_ONLY), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_USB_DEVICES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOW_USB_SERIAL), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdBluetoothGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_BLUETOOTH);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_BLUETOOTH), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdSudoGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_SUDO);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_SUDO), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_DEVICE_SUDO), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdNotificationGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_NOTIFICATION);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_NOTIFICATION), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdDistributedGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_DISTRIBUTED);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdMtpGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_MTP);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_MTP_CLIENT), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_USER_MTP_CLIENT), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdWifiGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_WIFI);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_WIFI), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_WIFI_LIST), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_WIFI_LIST), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdPrinterGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_PRINTER);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_DEVICE), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_PRINTER_IP_ADDRESS_FOR_ACCOUNT), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdRunningBundlesGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_RUNNING_BUNDLES);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::ALLOW_RUNNING_BUNDLES), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdFactoryResetGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_FACTORY_RESET);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::OPERATE_DEVICE), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::RESET_FACTORY), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::POLICY_CODE_END +
        EdmConstants::PolicyCode::DISABLE_RESET_FACTORY), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::POLICY_CODE_END +
        EdmConstants::PolicyCode::DISABLE_SECURE_ERASE), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdSuperHubGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_SUPERHUB);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::POLICY_CODE_END +
        EdmConstants::PolicyCode::DISABLE_SUPERHUB), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::POLICY_CODE_END +
        EdmConstants::PolicyCode::HIDDEN_SETTINGS_MENU), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdUpdatePolicyGroup, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto groupId = static_cast<int32_t>(ConflictGroupId::GROUP_UPDATE_POLICY);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::SET_OTA_UPDATE_POLICY), groupId);
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES), groupId);
}

HWTEST_F(ConflictGroupRegistryTest, TestGetConflictGroupIdUnregisteredPolicy, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    EXPECT_EQ(registry.GetConflictGroupId(0), static_cast<int32_t>(ConflictGroupId::NONE));
    EXPECT_EQ(registry.GetConflictGroupId(9999), static_cast<int32_t>(ConflictGroupId::NONE));
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_CAMERA),
        static_cast<int32_t>(ConflictGroupId::NONE));
    EXPECT_EQ(registry.GetConflictGroupId(EdmInterfaceCode::DISALLOWED_P2P),
        static_cast<int32_t>(ConflictGroupId::NONE));
}

HWTEST_F(ConflictGroupRegistryTest, TestDifferentGroupsReturnDifferentIds, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto usbGroup = registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_USB);
    auto bluetoothGroup = registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_BLUETOOTH);
    auto wifiGroup = registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_WIFI);
    EXPECT_NE(usbGroup, bluetoothGroup);
    EXPECT_NE(usbGroup, wifiGroup);
    EXPECT_NE(bluetoothGroup, wifiGroup);
    EXPECT_NE(usbGroup, static_cast<int32_t>(ConflictGroupId::NONE));
    EXPECT_NE(bluetoothGroup, static_cast<int32_t>(ConflictGroupId::NONE));
}

HWTEST_F(ConflictGroupRegistryTest, TestSameGroupPoliciesReturnSameId, TestSize.Level1)
{
    auto &registry = ConflictGroupRegistry::GetInstance();
    auto id1 = registry.GetConflictGroupId(EdmInterfaceCode::DISABLE_USB);
    auto id2 = registry.GetConflictGroupId(EdmInterfaceCode::ALLOWED_USB_DEVICES);
    auto id3 = registry.GetConflictGroupId(EdmInterfaceCode::USB_READ_ONLY);
    EXPECT_EQ(id1, id2);
    EXPECT_EQ(id2, id3);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
