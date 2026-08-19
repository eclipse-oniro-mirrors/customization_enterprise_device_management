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

#define private public
#define protected public
#include "policy_query_config_table.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

#include "iplugin.h"
#include "policy_query_config.h"
#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {

class PolicyQueryConfigTableTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}

    static void SetUpTestSuite(void)
    {
        Utils::SetEdmInitialEnv();
    }

    static void TearDownTestSuite(void)
    {
        Utils::ResetTokenTypeAndUid();
        ASSERT_TRUE(Utils::IsOriginalUTEnv());
        std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
    }
};

HWTEST_F(PolicyQueryConfigTableTest, TestGetConfigCount_NotZero, TestSize.Level1)
{
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    ASSERT_TRUE(count > 0);
}

HWTEST_F(PolicyQueryConfigTableTest, TestGetConfigCount_MinimumSize, TestSize.Level1)
{
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    ASSERT_TRUE(count >= 80);
}

HWTEST_F(PolicyQueryConfigTableTest, TestAllPolicyNamesValid, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(entries[i].config.policyName != nullptr && entries[i].config.policyName[0] != '\0')
            << "policyName empty for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestAllDataTypesValid, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(entries[i].config.dataType == PolicyDataType::BOOL ||
            entries[i].config.dataType == PolicyDataType::ARRAY_STRING ||
            entries[i].config.dataType == PolicyDataType::INT ||
            entries[i].config.dataType == PolicyDataType::STRING ||
            entries[i].config.dataType == PolicyDataType::CUSTOM)
            << "invalid dataType for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestAllApiTypesValid, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        ASSERT_TRUE(entries[i].config.apiType == IPlugin::ApiType::PUBLIC ||
            entries[i].config.apiType == IPlugin::ApiType::SYSTEM)
            << "invalid apiType for code " << entries[i].code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestAllSuperAdminPermissionNonEmpty, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        std::string perm = entries[i].config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        if (perm.empty()) {
            continue;
        }
        ASSERT_FALSE(perm.empty()) << "SUPER_DEVICE_ADMIN permission empty for code " << entries[i].code
            << " policyName=" << entries[i].config.policyName;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestFindConfig_ReturnsNonNullForValidCodes, TestSize.Level1)
{
    const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(EdmInterfaceCode::DISALLOWED_P2P);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(entry->code, static_cast<uint32_t>(EdmInterfaceCode::DISALLOWED_P2P));
}

HWTEST_F(PolicyQueryConfigTableTest, TestFindConfig_ReturnsNullForInvalidCodes, TestSize.Level1)
{
    const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(99999);
    ASSERT_EQ(entry, nullptr);
}

HWTEST_F(PolicyQueryConfigTableTest, TestIsFeatureEnabledConsistency, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    size_t enabledCount = 0;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].config.isFeatureEnabled) {
            enabledCount++;
        }
    }
    ASSERT_TRUE(enabledCount > 0);
    ASSERT_TRUE(enabledCount <= count);
}

static std::unordered_map<uint32_t, std::string> BuildExpectedSuperPermMap()
{
    std::unordered_map<uint32_t, std::string> map;
    map[EdmInterfaceCode::DISALLOWED_P2P] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY;
    map[EdmInterfaceCode::NTP_SERVER] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM;
    map[EdmInterfaceCode::SNAPSHOT_SKIP] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_TETHERING] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE] = EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY;
    map[EdmInterfaceCode::INACTIVE_USER_FREEZE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_UNMUTE_DEVICE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLED_APP_CLONE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_DEVICE_SUDO] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK] = EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION;
    map[EdmInterfaceCode::DISABLE_SET_DEVICE_NAME] = EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION;
    map[EdmInterfaceCode::DISABLE_MAINTENANCE_MODE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_MTP_CLIENT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_MTP_SERVER] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_USER_MTP_CLIENT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_MODIFY_DATETIME] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY;
    map[EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY;
    map[EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
    map[EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
    map[EdmInterfaceCode::GET_DISPLAY_VERSION] = EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO;
    map[EdmInterfaceCode::GET_SECURITY_PATCH_TAG] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::WATERMARK_IMAGE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::PERMISSION_MANAGED_STATE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION;
    map[EdmInterfaceCode::DISALLOWED_PERMISSION] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::GET_BUNDLE_INFO_LIST] = EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO;
    map[EdmInterfaceCode::GET_BUNDLE_STORAGE_STATS] = EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO;
    map[EdmInterfaceCode::QUERY_BUNDLE_STATS_INFOS] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
    map[EdmInterfaceCode::DISALLOWED_UINPUT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_CORE_DUMP] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_RS232] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_X_KEY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOW_USB_SERIAL] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_TRAFFIC_REDIRECTION] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::IS_APP_KIOSK_ALLOWED] = "";
#ifdef CAMERA_FRAMEWORK_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_CAMERA] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef BLUETOOTH_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_BLUETOOTH] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH;
    map[EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH;
#endif
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
    map[EdmInterfaceCode::DISABLED_HDC] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_MICROPHONE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLED_PRINTER] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef USB_SERVICE_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_USB] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::ALLOWED_USB_DEVICES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB;
#endif
#ifdef USB_DISK_MANAGER_EDM_ENABLE
    map[EdmInterfaceCode::USB_READ_ONLY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef SUDO_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_SUDO] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef PRIVATE_SPACE_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_PRIVATE_SPACE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef OS_ACCOUNT_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT] = EdmPermission::PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY;
    map[EdmInterfaceCode::DISABLED_PRINT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef APN_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOW_MODIFY_APN] = EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION;
#endif
#ifdef POWER_MANAGER_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS] = EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION;
#endif
#ifdef WIFI_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_WIFI] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::ALLOWED_WIFI_LIST] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI;
    map[EdmInterfaceCode::DISALLOWED_WIFI_LIST] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI;
#endif
#ifdef NETMANAGER_EXT_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOW_VPN] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef SMS_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_SMS] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef MMS_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_MMS] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef TELEPHONY_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::TELEPHONY_CALL_POLICY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY;
#endif
#ifdef SAMBA_EDM_ENABLE
    map[EdmInterfaceCode::DISABLE_SAMBA_CLIENT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_SAMBA_SERVER] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef FEATURE_PC_ONLY
    map[EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM;
    map[EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM;
    map[EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM;
    map[EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP] = EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION;
    map[EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLED_HDC_REMOTE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
    map[EdmInterfaceCode::DISABLE_RUNNING_BINARY_APP] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef NOTIFICATION_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_NOTIFICATION] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef MOBILE_DATA_ENABLE
    map[EdmInterfaceCode::DISALLOWED_MOBILE_DATA] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK;
#endif
#ifdef NET_MANAGER_BASE_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK;
#endif
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef MULTI_WINDOW_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOWED_MULTI_WINDOW] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef ABILITY_RUNTIME_EDM_ENABLE
    map[EdmInterfaceCode::ALLOW_RUNNING_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
    map[EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
#endif
#ifdef USERIAM_EDM_ENABLE
    map[EdmInterfaceCode::PASSWORD_POLICY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY;
    map[EdmInterfaceCode::FINGERPRINT_AUTH] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef LOCATION_EDM_ENABLE
    map[EdmInterfaceCode::LOCATION_POLICY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCATION;
#endif
#ifdef PASTEBOARD_EDM_ENABLE
    map[EdmInterfaceCode::CLIPBOARD_POLICY] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
    map[EdmInterfaceCode::SET_BROWSER_POLICIES] = "";
#endif
#ifdef OS_ACCOUNT_EDM_ENABLE
    map[EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER] = EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS;
#endif
#ifndef FEATURE_PC_ONLY
    map[EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::HIDE_LAUNCHER_ICON] =
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
#endif
    return map;
}

HWTEST_F(PolicyQueryConfigTableTest, TestExactSuperAdminPermissions, TestSize.Level1)
{
    auto expectedMap = BuildExpectedSuperPermMap();
    for (auto& [code, expectedPerm] : expectedMap) {
        const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(code);
        if (entry == nullptr || !entry->config.isFeatureEnabled) {
            continue;
        }
        std::string actualPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(actualPerm, expectedPerm) << "permission mismatch for code " << code
            << " policyName=" << entry->config.policyName;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestRestrictionPermissionByodEntries, TestSize.Level1)
{
    std::vector<uint32_t> byodEntries = {
        EdmInterfaceCode::DISALLOWED_P2P,
        EdmInterfaceCode::DISALLOWED_TETHERING,
    };
#ifdef CAMERA_FRAMEWORK_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLE_CAMERA);
#endif
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLE_MICROPHONE);
#endif
#ifdef WIFI_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLE_WIFI);
#endif

#ifdef PASTEBOARD_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::CLIPBOARD_POLICY);
#endif
#ifdef USB_DISK_MANAGER_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::USB_READ_ONLY);
#endif
#ifdef BLUETOOTH_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLE_BLUETOOTH);
#endif
#ifdef USB_SERVICE_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLE_USB);
#endif
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISABLED_HDC);
#endif
#ifdef SUDO_EDM_ENABLE
    byodEntries.push_back(EdmInterfaceCode::DISALLOWED_SUDO);
#endif
    for (uint32_t code : byodEntries) {
        const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(code);
        if (entry == nullptr || !entry->config.isFeatureEnabled) {
            continue;
        }
        std::string byodPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(byodPerm, EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS)
            << "BYOD permission mismatch for code " << code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestRestrictionNoByodEntries, TestSize.Level1)
{
    std::vector<uint32_t> superOnlyEntries = {
        EdmInterfaceCode::DISABLED_APP_CLONE,
        EdmInterfaceCode::INACTIVE_USER_FREEZE,
        EdmInterfaceCode::DISALLOWED_DEVICE_SUDO,
        EdmInterfaceCode::DISALLOW_UNMUTE_DEVICE,
        EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE,
        EdmInterfaceCode::DISABLE_MTP_CLIENT,
        EdmInterfaceCode::DISABLE_USER_MTP_CLIENT,
        EdmInterfaceCode::DISALLOWED_UINPUT,
        EdmInterfaceCode::DISALLOW_CORE_DUMP,
        EdmInterfaceCode::DISALLOW_RS232,
        EdmInterfaceCode::DISALLOW_X_KEY,
        EdmInterfaceCode::DISALLOW_USB_SERIAL,
        EdmInterfaceCode::DISALLOWED_TRAFFIC_REDIRECTION,
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION,
        EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL,
    };
#ifdef OS_ACCOUNT_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLED_PRINT);
#endif
#ifdef SUDO_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_SUDO);
#endif
#ifdef SAMBA_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLE_SAMBA_CLIENT);
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLE_SAMBA_SERVER);
#endif
#ifdef FEATURE_PC_ONLY
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY);
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLED_HDC_REMOTE);
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE);
#endif
#ifdef SMS_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_SMS);
#endif
#ifdef MMS_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_MMS);
#endif
#ifdef TELEPHONY_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL);
#endif
#ifdef NETMANAGER_EXT_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOW_VPN);
#endif
#ifdef WIFI_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS);
#endif
#ifdef NOTIFICATION_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_NOTIFICATION);
#endif
#ifdef PRIVATE_SPACE_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLE_PRIVATE_SPACE);
#endif
#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISABLE_BACKUP_AND_RESTORE);
#endif
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD);
#endif
#ifdef FEATURE_PC_ONLY
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN);
#endif
#ifdef MULTI_WINDOW_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOWED_MULTI_WINDOW);
#endif
#ifdef OS_ACCOUNT_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOW_MODIFY_WALLPAPER);
#endif
#ifdef APN_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::DISALLOW_MODIFY_APN);
#endif
#ifdef USERIAM_EDM_ENABLE
    superOnlyEntries.push_back(EdmInterfaceCode::FINGERPRINT_AUTH);
#endif
    for (uint32_t code : superOnlyEntries) {
        const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(code);
        if (entry == nullptr || !entry->config.isFeatureEnabled) {
            continue;
        }
        std::string byodPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(byodPerm, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS)
            << "RestrictionPermission(no-byod) BYOD permission mismatch for code " << code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestTagPermissionEntries, TestSize.Level1)
{
    std::vector<std::pair<uint32_t, std::string>> tagPermEntries = {
        {EdmInterfaceCode::DISALLOW_MODIFY_DATETIME, EdmPermission::PERMISSION_ENTERPRISE_SET_DATETIME},
#ifdef BLUETOOTH_EDM_ENABLE
        {EdmInterfaceCode::DISABLE_BLUETOOTH, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH},
#endif
#ifdef AUDIO_FRAMEWORK_EDM_ENABLE
        {EdmInterfaceCode::DISABLED_HDC, EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY},
        {EdmInterfaceCode::DISABLED_PRINTER, EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY},
#endif
#ifdef USB_SERVICE_EDM_ENABLE
        {EdmInterfaceCode::DISABLE_USB, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB},
#endif
#ifdef USB_DISK_MANAGER_EDM_ENABLE
        {EdmInterfaceCode::USB_READ_ONLY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB},
#endif
#ifdef WIFI_EDM_ENABLE
        {EdmInterfaceCode::DISABLE_WIFI, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI},
#endif
#ifdef ABILITY_RUNTIME_EDM_ENABLE
        {EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY},
#endif
#ifdef USERIAM_EDM_ENABLE
        {EdmInterfaceCode::PASSWORD_POLICY, ""},
#endif
    };
    for (auto& [code, expectedTagPerm] : tagPermEntries) {
        const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(code);
        if (entry == nullptr || !entry->config.isFeatureEnabled) {
            continue;
        }
        ASSERT_EQ(entry->config.permissionConfig.pattern, PermissionPattern::TAG) << "code " << code << " should have tag permission";
        std::string tagPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "test_tag");
        ASSERT_EQ(tagPerm, expectedTagPerm) << "tagPermission mismatch for code " << code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestSpecificPermissionEntries, TestSize.Level1)
{
    std::vector<std::pair<uint32_t, std::string>> specificPermEntries = {
        {EdmInterfaceCode::GET_DISPLAY_VERSION, EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO},
        {EdmInterfaceCode::GET_SECURITY_PATCH_TAG, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::WATERMARK_IMAGE, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::PERMISSION_MANAGED_STATE, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USER_GRANT_PERMISSION},
        {EdmInterfaceCode::ALLOWED_INSTALL_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY},
        {EdmInterfaceCode::DISALLOWED_INSTALL_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY},
        {EdmInterfaceCode::DISALLOWED_UNINSTALL_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY},
        {EdmInterfaceCode::NTP_SERVER, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM},
        {EdmInterfaceCode::ALLOWED_INSTALL_APP_TYPE, EdmPermission::PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY},
        {EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION},
        {EdmInterfaceCode::DISABLE_SET_DEVICE_NAME, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION},
        {EdmInterfaceCode::DISALLOWED_PERMISSION, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::ALLOWED_PERMISSION_BUNDLE, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::DEVICE_SECURITY_LEVEL_POLICY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
        {EdmInterfaceCode::GET_BUNDLE_INFO_LIST, EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO},
        {EdmInterfaceCode::GET_BUNDLE_STORAGE_STATS, EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO},
        {EdmInterfaceCode::QUERY_BUNDLE_STATS_INFOS, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION},
        {EdmInterfaceCode::ALLOWED_NOTIFICATION_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION},
        {EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION},
#ifdef FEATURE_PC_ONLY
        {EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM},
        {EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM},
        {EdmInterfaceCode::SET_AUTO_UNLOCK_AFTER_REBOOT, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM},
        {EdmInterfaceCode::DISALLOW_MODIFY_ETHERNET_IP, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION},
        {EdmInterfaceCode::DISABLE_RUNNING_BINARY_APP, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY},
#endif
#ifdef LOCATION_EDM_ENABLE
        {EdmInterfaceCode::LOCATION_POLICY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_LOCATION},
#endif
#ifdef TELEPHONY_EDM_ENABLE
        {EdmInterfaceCode::TELEPHONY_CALL_POLICY, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY},
#endif
#ifdef BLUETOOTH_EDM_ENABLE
        {EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH},
        {EdmInterfaceCode::DISALLOWED_BLUETOOTH_DEVICES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH},
#endif
#ifdef USB_SERVICE_EDM_ENABLE
        {EdmInterfaceCode::ALLOWED_USB_DEVICES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB},
#endif
#ifdef WIFI_EDM_ENABLE
        {EdmInterfaceCode::ALLOWED_WIFI_LIST, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI},
        {EdmInterfaceCode::DISALLOWED_WIFI_LIST, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI},
#endif
#ifdef OS_ACCOUNT_EDM_ENABLE
        {EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, EdmPermission::PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY},
#endif
#ifdef APN_EDM_ENABLE
        {EdmInterfaceCode::DISALLOW_MODIFY_APN, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION},
#endif
#ifdef POWER_MANAGER_EDM_ENABLE
        {EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION},
#endif
#ifdef MOBILE_DATA_ENABLE
        {EdmInterfaceCode::DISALLOWED_MOBILE_DATA, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK},
#endif
#ifdef NET_MANAGER_BASE_EDM_ENABLE
        {EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK},
#endif
#ifdef FEATURE_PC_ONLY
        {EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS},
#endif
#ifdef EXTERNAL_DISK_MANAGER_EDM_ENABLE
        {EdmInterfaceCode::DISALLOWED_EXTERNAL_STORAGE_CARD, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS},
#endif
#ifdef ABILITY_RUNTIME_EDM_ENABLE
        {EdmInterfaceCode::ALLOW_RUNNING_BUNDLES, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION},
#endif
#ifdef COMMON_EVENT_SERVICE_EDM_ENABLE
        {EdmInterfaceCode::SET_BROWSER_POLICIES, ""},
#endif
#ifdef MULTI_WINDOW_EDM_ENABLE
        {EdmInterfaceCode::DISALLOWED_MULTI_WINDOW, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS},
#endif
#ifndef FEATURE_PC_ONLY
        {EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::HIDE_LAUNCHER_ICON,
            EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION},
#endif
    };
    for (auto& [code, expectedPerm] : specificPermEntries) {
        const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(code);
        if (entry == nullptr || !entry->config.isFeatureEnabled) {
            continue;
        }
        ASSERT_NE(entry->config.permissionConfig.pattern, PermissionPattern::TAG) << "code " << code << " should NOT have tag permission";
        std::string superPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
        ASSERT_EQ(superPerm, expectedPerm) << "specificPermission mismatch for code " << code;
        std::string byodPerm = entry->config.permissionConfig.GetPermission(
            IPlugin::PermissionType::BYOD_DEVICE_ADMIN, "");
        ASSERT_EQ(byodPerm, expectedPerm) << "specificPermission BYOD mismatch for code " << code;
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestInvalidCode, TestSize.Level1)
{
    const PolicyQueryConfigEntry* entry = PolicyQueryConfigTable::FindConfig(99999);
    ASSERT_EQ(entry, nullptr);
}

HWTEST_F(PolicyQueryConfigTableTest, TestIsPolicySavedConsistency, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 0; i < count; i++) {
        if (entries[i].config.dataType != PolicyDataType::CUSTOM) {
            ASSERT_TRUE(entries[i].config.isPolicySaved) << "non-CUSTOM type should have isPolicySaved=true for code " << entries[i].code;
        }
    }
}

HWTEST_F(PolicyQueryConfigTableTest, TestConfigTableSorted, TestSize.Level1)
{
    auto entries = PolicyQueryConfigTable::GetAllEntries();
    size_t count = PolicyQueryConfigTable::GetConfigCount();
    for (size_t i = 1; i < count; i++) {
        ASSERT_TRUE(entries[i - 1].code < entries[i].code)
            << "config table not sorted at index " << i << " codes " << entries[i - 1].code << " and " << entries[i].code;
    }
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
