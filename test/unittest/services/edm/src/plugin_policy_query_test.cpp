/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define protected public
#include "ipolicy_query.h"
#undef protected

#ifdef FEATURE_PC_ONLY
#include "disallow_modify_ethernet_ip_query.h"
#endif

#ifdef PRIVATE_SPACE_EDM_ENABLE
#include "disable_private_space_query.h"
#endif

#include "allowed_app_distribution_types_query.h"
#include "allowed_bluetooth_devices_query.h"
#include "allowed_usb_devices_query.h"
#include "allowed_wifi_list_query.h"
#include "cJSON.h"
#include "cjson_serializer.h"
#include "clipboard_info.h"
#include "clipboard_policy.h"
#include "clipboard_policy_query.h"
#include "clipboard_policy_serializer.h"
#include "disable_backup_and_restore_query.h"
#include "disable_bluetooth_query.h"
#include "disable_camera_query.h"
#include "disable_hdc_query.h"
#include "disable_microphone_query.h"
#include "disable_printer_query.h"
#include "disable_maintenance_mode_query.h"
#include "disable_mtp_client_query.h"
#include "disable_mtp_server_query.h"
#include "disable_samba_client_query.h"
#include "disable_samba_server_query.h"
#include "disable_set_biometrics_and_screenLock_query.h"
#include "disable_set_device_name_query.h"
#include "disable_user_mtp_client_query.h"
#include "disable_usb_query.h"
#include "disallow_add_local_account_query.h"
#include "disallow_distributed_transmission_query.h"
#include "disallow_modify_datetime_query.h"
#include "disallowed_airplane_mode_query.h"
#include "disallowed_bluetooth_devices_query.h"
#include "disallowed_install_bundles_query.h"
#include "disallowed_running_bundles_query.h"
#include "disallowed_tethering_query.h"
#include "disallowed_uninstall_bundles_query.h"
#include "disallowed_wifi_list_query.h"
#include "disallow_modify_apn_query.h"
#include "edm_constants.h"
#include "fingerprint_auth_query.h"
#include "get_device_encryption_status_query.h"
#include "get_display_version_query.h"
#include "get_security_patch_tag_query.h"
#include "is_app_kiosk_allowed_query.h"
#include "inactive_user_freeze_query.h"
#include "location_policy_query.h"
#include "ntp_server_query.h"
#include "parameters.h"
#include "password_policy.h"
#include "password_policy_query.h"
#include "password_policy_serializer.h"
#include "set_browser_policies_query.h"
#include "set_wifi_disabled_query.h"
#include "snapshot_skip_query.h"
#include "usb_read_only_query.h"
#include "disallowed_sms_query.h"
#include "disallowed_mms_query.h"
#include "disallow_power_long_press_query.h"

#ifdef FEATURE_PC_ONLY
#include "get_auto_unlock_after_reboot_query.h"
#include "disable_usb_storage_device_write_query.h"
#endif

#ifdef SUDO_EDM_ENABLE
#include "disable_sudo_query.h"
#endif

#ifdef NOTIFICATION_EDM_ENABLE
#include "disallowed_notification_query.h"
#endif

#ifdef NETMANAGER_EXT_EDM_ENABLE
#include "disallow_vpn_query.h"
#endif

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
class PluginPolicyQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;
};
const std::string POLICY_DATA = "[{\"tokenId\":1,\"userId\":100,\"bundleName\":\"com.ohos.test1\","
    "\"clipboardPolicy\":1},{\"tokenId\":2,\"userId\":100,\"bundleName\":\"com.ohos.test2\",\"clipboardPolicy\":2}]";
const std::string TEST_VALUE_COMPLEXITYREG = "^(?=.*[a-zA-Z]).{1,9}$";
const int TEST_VALUE_VALIDITY_PERIOD = 2;
const std::string TEST_VALUE_ADDITIONAL_DESCRIPTION = "testDescription";
const std::string TEST_POLICY_DATA =
    "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
    "\"additionalDescription\": \"testDescription\"}";
const std::string PERSIST_BLUETOOTH_CONTROL = "persist.edm.prohibit_bluetooth";
const std::string PERSIST_EDM_SET_BIOMETRICS_AND_SCREENLOCK_DISABLE =
    "persist.edm.set_biometrics_and_screenLock_disable";
const std::string PERSIST_EDM_SET_DEVICE_NAME_DISABLE =
    "persist.edm.set_device_name_disable";
const std::string TEST_PERMISSION_TAG_VERSION_11 = "version_11";
const std::string TEST_PERMISSION_TAG_VERSION_12 = "version_12";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH = "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_USB = "ohos.permission.ENTERPRISE_MANAGE_USB";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_SECURITY = "ohos.permission.ENTERPRISE_MANAGE_SECURITY";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS = "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";
const std::string TEST_PERMISSION_PERSONAL_MANAGE_RESTRICTIONS = "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS";
const std::string TEST_PERMISSION_ENTERPRISE_RESTRICT_POLICY = "ohos.permission.ENTERPRISE_RESTRICT_POLICY";
const std::string TEST_PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY = "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY";
const std::string TEST_PERMISSION_ENTERPRISE_SET_DATETIME = "ohos.permission.ENTERPRISE_SET_DATETIME";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_WIFI = "ohos.permission.ENTERPRISE_MANAGE_WIFI";
const std::string TEST_PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY =
    "ohos.permission.ENTERPRISE_SET_BUNDLE_INSTALL_POLICY";
const std::string TEST_PERMISSION_ENTERPRISE_GET_DEVICE_INFO = "ohos.permission.ENTERPRISE_GET_DEVICE_INFO";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_NETWORK = "ohos.permission.ENTERPRISE_MANAGE_NETWORK";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_SYSTEM = "ohos.permission.ENTERPRISE_MANAGE_SYSTEM";
const std::string TEST_PERMISSION_ENTERPRISE_SET_USER_RESTRICTION = "ohos.permission.ENTERPRISE_SET_USER_RESTRICTION";
void PluginPolicyQueryTest::SetUp() {}

void PluginPolicyQueryTest::TearDown() {}

/**
 * @tc.name: TestAllowedBluetoothDevicesQuery
 * @tc.desc: Test AllowedBluetoothDevicesQuery::QueryPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedBluetoothDevicesQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedBluetoothDevicesQuery>();
    std::string policyValue{"GetBluetoothDevices"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedBluetoothDevicesQuery001
 * @tc.desc: Test AllowedBluetoothDevicesQuery GetPolicyName and GetPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedBluetoothDevicesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedBluetoothDevicesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH);
    ASSERT_TRUE(queryObj->GetPolicyName() == "allowed_bluetooth_devices");
}

/**
 * @tc.name: TestDisallowedBluetoothDevicesQuery
 * @tc.desc: Test DisallowedBluetoothDevicesQuery::QueryPolicy func.
 * @tc.type: FUNC
 */
    HWTEST_F(PluginPolicyQueryTest, TestDisallowedBluetoothDevicesQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedBluetoothDevicesQuery>();
    std::string policyValue{"GetBluetoothDevices"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedBluetoothDevicesQuery001
 * @tc.desc: Test DisallowedBluetoothDevicesQuery GetPolicyName and GetPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedBluetoothDevicesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedBluetoothDevicesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
    == TEST_PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_bluetooth_devices");
}

/**
 * @tc.name: TestAllowedAppDistributionTypesQuery001
 * @tc.desc: Test AllowedAppDistributionTypesQuery::QueryPolicy func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedAppDistributionTypesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedAppDistributionTypesQuery>();
    std::string policyValue{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedAppDistributionTypesQuery002
 * @tc.desc: Test AllowedAppDistributionTypesQuery GetPolicyName and GetPermission func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedAppDistributionTypesQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedAppDistributionTypesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "allowed_install_app_type");
}

/**
 * @tc.name: TestAllowedUsbDevicesQuery
 * @tc.desc: Test EnterpriseAdminConnection::OnAbilityConnectDone func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedUsbDevicesQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedUsbDevicesQuery>();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedUsbDevicesQuery001
 * @tc.desc: Test AllowedUsbDevicesQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedUsbDevicesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedUsbDevicesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_USB);
    ASSERT_TRUE(queryObj->GetPolicyName() == "allowed_usb_devices");
}

/**
 * @tc.name: TestAllowedWifiListQuery001
 * @tc.desc: Test AllowedWifiListQuery::QueryPolicy
 * @tc.type: FUNC
 */
    HWTEST_F(PluginPolicyQueryTest, TestAllowedWifiListQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedWifiListQuery>();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAllowedWifiListQuery002
 * @tc.desc: Test AllowedWifiListQuery::QueryPolicy
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedWifiListQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedWifiListQuery>();
    std::string policyData = R"({"key": "value"})";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestAllowedWifiListQuery003
 * @tc.desc: Test Test AllowedWifiListQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestAllowedWifiListQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<AllowedWifiListQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
    == TEST_PERMISSION_ENTERPRISE_MANAGE_WIFI);
    ASSERT_TRUE(queryObj->GetPolicyName() == "allowed_wifi_list");
}

/**
 * @tc.name: TestDisallowedWifiListQuery001
 * @tc.desc: Test AllowedWifiListQuery::QueryPolicy
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedWifiListQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedWifiListQuery>();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedWifiListQuery002
 * @tc.desc: Test DisallowedWifiListQuery::QueryPolicy
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedWifiListQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedWifiListQuery>();
    std::string policyData = R"({"key": "value"})";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestDisallowedWifiListQuery003
 * @tc.desc: Test Test DisallowedWifiListQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedWifiListQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedWifiListQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
    == TEST_PERMISSION_ENTERPRISE_MANAGE_WIFI);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_wifi_list");
}

/**
 * @tc.name: TestClipboardPolicyQuery
 * @tc.desc: Test ClipboardPolicyQuery::QueryPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(5);
    std::string policyData = POLICY_DATA;
    queryObj->QueryPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardInfo> policyMap;
    auto serializer = ClipboardSerializer::GetInstance();
    serializer->Deserialize(policy, policyMap);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyMap.size() == 2);
}

/**
 * @tc.name: TestClipboardPolicyQuery002
 * @tc.desc: Test ClipboardPolicyPluginTest::QueryPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = POLICY_DATA;
    data.WriteInt32(3);
    data.WriteInt32(1);
    queryObj->QueryPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardInfo> policyMap;
    auto serializer = ClipboardSerializer::GetInstance();
    serializer->Deserialize(policy, policyMap);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyMap[1].policy == ClipboardPolicy::IN_APP);
}

/**
 * @tc.name: TestClipboardPolicyQuery003
 * @tc.desc: Test ClipboardPolicyQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "clipboard_policy");
}

/**
 * @tc.name: TestDisableBluetoothQuery001
 * @tc.desc: Test DisableBluetoothQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBluetoothQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableBluetoothQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(OHOS::system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false),
        reply.ReadBool());
}

/**
 * @tc.name: TestDisableBluetoothQuery002
 * @tc.desc: Test DisableBluetoothQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBluetoothQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableBluetoothQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisableBluetoothQuery003
 * @tc.desc: Test DisableBluetoothQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBluetoothQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableBluetoothQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH);
    
    permissionTag = TEST_PERMISSION_TAG_VERSION_12;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_bluetooth");
}

/**
 * @tc.name: DisablePrinterQuery001
 * @tc.desc: Test DisablePrinterPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisablePrinterQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisablePrinterQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisablePrinterQuery002
 * @tc.desc: Test DisablePrinterQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisablePrinterQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisablePrinterQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_RESTRICT_POLICY);
    
    permissionTag = TEST_PERMISSION_TAG_VERSION_12;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_printer");
}

/**
 * @tc.name: DisableMtpClientQuery001
 * @tc.desc: Test DisableMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMtpClientQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableMtpClientQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableMtpClientQuery002
 * @tc.desc: Test DisableMtpClientQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMtpClientQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableMtpClientQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_mtp_client");
}

/**
 * @tc.name: DisableMtpServerQuery001
 * @tc.desc: Test DisableMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMtpServerQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableMtpServerQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableMtpServerQuery002
 * @tc.desc: Test DisableMtpServerQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMtpServerQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableMtpServerQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_mtp_server");
}

/**
 * @tc.name: DisableUserMtpClientQuery001
 * @tc.desc: Test DisableUserMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUserMtpClientQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableUserMtpClientQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableUserMtpClientQuery002
 * @tc.desc: Test DisableUserMtpClientQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUserMtpClientQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableUserMtpClientQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_user_mtp_client");
}

/**
 * @tc.name: DisableSambaClientQuery001
 * @tc.desc: Test DisableSambaPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSambaClientQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableSambaClientQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableSambaClientQuery002
 * @tc.desc: Test DisableSambaClientQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSambaClientQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSambaClientQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
    == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISABLED_SAMBA_CLIENT);
}

/**
 * @tc.name: DisableSambaServerQuery001
 * @tc.desc: Test DisableSambaPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSambaServerQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableSambaServerQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableSambaServerQuery002
 * @tc.desc: Test DisableSambaServerQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSambaServerQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSambaServerQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
    == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISABLED_SAMBA_SERVER);
}

/**
 * @tc.name: DisableMaintenanceModeQuery001
 * @tc.desc: Test DisableMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMaintenanceModeQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableMaintenanceModeQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: DisableMaintenanceModeQuery002
 * @tc.desc: Test DisableMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMaintenanceModeQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableMaintenanceModeQuery>();
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisableMaintenanceModeQuery003
 * @tc.desc: Test DisableMaintenanceModeQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableMaintenanceModeQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableMaintenanceModeQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disabled_maintenance_mode");
}

/**
 * @tc.name: TestDisableUsbQuery
 * @tc.desc: Test DisableUsbQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUsbQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableUsbQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableUsbQuery001
 * @tc.desc: Test DisableUsbQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUsbQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableUsbQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_USB);
    
    permissionTag = TEST_PERMISSION_TAG_VERSION_12;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disable_usb");
}

/**
 * @tc.name: TestDisallowAddLocalAccountQuery
 * @tc.desc: Test DisallowAddLocalAccountQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowAddLocalAccountQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisallowAddLocalAccountQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisallowAddLocalAccountQuery001
 * @tc.desc: Test DisallowAddLocalAccountQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowAddLocalAccountQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowAddLocalAccountQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallow_add_local_account");
}

/**
 * @tc.name: TestDisallowModifyDateTimeQuery
 * @tc.desc: Test TestDisallowModifyDateTimeQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyDateTimeQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisallowModifyDateTimeQuery>();
    // origin policy is disallow to modify date time.
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    // get policy is disallow to modify date time.
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisallowModifyDateTimeQuery001
 * @tc.desc: Test DisallowModifyDateTimeQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyDateTimeQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyDateTimeQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_DATETIME);
    
    permissionTag = TEST_PERMISSION_TAG_VERSION_12;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallow_modify_datetime");
}

/**
 * @tc.name: TestFingerprintAuthQuery001
 * @tc.desc: Test FingerprintAuthQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestFingerprintAuthQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<FingerprintAuthQuery>();
    MessageParcel data;
    data.WriteString(EdmConstants::FINGERPRINT_AUTH_TYPE);
    MessageParcel reply;
    std::string policyData = "true";
    plugin->QueryPolicy(policyData, data, reply, 100);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestFingerprintAuthQuery002
 * @tc.desc: Test FingerprintAuthQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestFingerprintAuthQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<FingerprintAuthQuery>();
    MessageParcel data;
    data.WriteString(EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE);
    data.WriteInt32(100);
    MessageParcel reply;
    std::string policyData = "[100]";
    plugin->QueryPolicy(policyData, data, reply, 100);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestFingerprintAuthQuery003
 * @tc.desc: Test FingerprintAuthQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestFingerprintAuthQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<FingerprintAuthQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "fingerprint_auth");
}

/**
 * @tc.name: TestGetDeviceEncryptionStatusQuery
 * @tc.desc: Test get device encryption status function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetDeviceEncryptionStatusQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<GetDeviceEncryptionStatusQuery>();
    std::string policyValue{"GetDeviceEncryptionStatus"};
    MessageParcel data;
    MessageParcel reply;
    plugin->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadBool() == true);
}

/**
 * @tc.name: TestGetDeviceEncryptionStatusQuery001
 * @tc.desc: Test GetDeviceEncryptionStatusQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetDeviceEncryptionStatusQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetDeviceEncryptionStatusQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "get_device_encryption_status");
}

/**
 * @tc.name: TestGetSecurityPatchTagSuc
 * @tc.desc: Test get security patch tag function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetSecurityPatchTagSuc, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<GetSecurityPatchTagQuery>();
    std::string policyValue{"GetSecurityPatchTag"};
    MessageParcel data;
    MessageParcel reply;
    plugin->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadString() != "");
}

/**
 * @tc.name: TestGetSecurityPatchTagQuery001
 * @tc.desc: Test GetSecurityPatchTagQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetSecurityPatchTagQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetSecurityPatchTagQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "get_security_patch_tag");
}

/**
 * @tc.name: TestUsbReadOnlyQuery001
 * @tc.desc: Test UsbReadOnlyQuery::QueryPolicy function when policy is read only.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestUsbReadOnlyQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<UsbReadOnlyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{"1"};
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 1);
}

/**
 * @tc.name: TestUsbReadOnlyQuery002
 * @tc.desc: Test UsbReadOnlyQuery::QueryPolicy function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestUsbReadOnlyQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<UsbReadOnlyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{"2"};
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 2);
}

/**
 * @tc.name: TestUsbReadOnlyQuery003
 * @tc.desc: Test UsbReadOnlyQuery::QueryPolicy function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestUsbReadOnlyQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<UsbReadOnlyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{""};
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 0);
}

/**
 * @tc.name: TestUsbReadOnlyQuery004
 * @tc.desc: Test UsbReadOnlyQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestUsbReadOnlyQuery004, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<UsbReadOnlyQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_USB);
    ASSERT_TRUE(queryObj->GetPolicyName() == "usb_read_only");
}

/**
 * @tc.name: TestSetWifiDisabledQuery
 * @tc.desc: Test SetWifiDisabledQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestSetWifiDisabledQuery, TestSize.Level1)
{
    const std::string KEY_DISABLE_WIFI = "persist.edm.wifi_enable";
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<SetWifiDisabledQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result == system::GetBoolParameter(KEY_DISABLE_WIFI, false));
}

/**
 * @tc.name: TestSetWifiDisabledQuery001
 * @tc.desc: Test SetWifiDisabledQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestSetWifiDisabledQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<SetWifiDisabledQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_WIFI);
    
    permissionTag = TEST_PERMISSION_TAG_VERSION_12;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disable_wifi");
}

/**
 * @tc.name: TestDisableBluetoothQuery
 * @tc.desc: Test DisableBluetoothPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBluetoothQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableBluetoothQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(OHOS::system::GetBoolParameter(PERSIST_BLUETOOTH_CONTROL, false),
        reply.ReadBool());
}

/**
 * @tc.name: TestPasswordPolicyQuery
 * @tc.desc: Test PasswordPolicyQuery::QueryPolicy when policyData is empty
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<PasswordPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.empty());
}

/**
 * @tc.name: TestPasswordPolicyQuery002
 * @tc.desc: Test PasswordPolicyQuery::QueryPolicy when policyData is err
 * and policies is err.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQuery002, TestSize.Level1)
{
    const std::string TEST_POLICY_ERR_DATA =
        "{\"comple\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
        "\"additionalDescription\": \"testDescription\"}";
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<PasswordPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = TEST_POLICY_ERR_DATA;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestPasswordPolicyQuery003
 * @tc.desc: Test PasswordPolicyQuery::QueryPolicy
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<PasswordPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, 0);
    ASSERT_TRUE(ret == ERR_OK);
    auto serializer_ = PasswordSerializer::GetInstance();
    PasswordPolicy policy;
    serializer_->Deserialize(policyData, policy);
    ASSERT_TRUE(policy.additionalDescription == TEST_VALUE_ADDITIONAL_DESCRIPTION);
    ASSERT_TRUE(policy.validityPeriod == TEST_VALUE_VALIDITY_PERIOD);
    ASSERT_TRUE(policy.complexityReg == TEST_VALUE_COMPLEXITYREG);
}

/**
 * @tc.name: TestPasswordPolicyQuery004
 * @tc.desc: Test PasswordPolicyQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestPasswordPolicyQuery004, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<PasswordPolicyQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "password_policy");
}

/**
 * @tc.name: TestSetBrowserPoliciesQuery
 * @tc.desc: Test SetBrowserPoliciesQuery::QueryPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestSetBrowserPoliciesQuery, TestSize.Level1)
{
    const std::string TestAppId = "test_app_id";
    const std::string TestPolicyData = "{\"test_app_id\": {\"test_policy_name\":\"test_policy_value\"}}";
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<SetBrowserPoliciesQuery>();
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TestAppId);
    std::string policyData = TestPolicyData;
    plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    auto serializer = CjsonSerializer::GetInstance();
    cJSON* root = nullptr;
    serializer->Deserialize(TestPolicyData, root);
    cJSON* policy = cJSON_GetObjectItem(root, TestAppId.c_str());
    std::string retString;
    serializer->Serialize(policy, retString);
    ASSERT_TRUE(reply.ReadString() == retString);
}

/**
 * @tc.name: TestDisallowedInstallBundlesQuery001
 * @tc.desc: Test DisallowedInstallBundlesQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedInstallBundlesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedInstallBundlesQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedInstallBundlesQuery002
 * @tc.desc: Test DisallowedInstallBundlesQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedInstallBundlesQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedInstallBundlesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_install_bundles");
}

/**
 * @tc.name: TestDisallowedThtheringQuery001
 * @tc.desc: Test DisallowedThtheringQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedThtheringQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedThtheringQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedThtheringQuery002
 * @tc.desc: Test DisallowedThtheringQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedThtheringQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedThtheringQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_tethering");
}

/**
 * @tc.name: TestDisallowedUninstallBundlesQuery001
 * @tc.desc: Test DisallowedUninstallBundlesQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedUninstallBundlesQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedUninstallBundlesQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedUninstallBundlesQuery002
 * @tc.desc: Test DisallowedUninstallBundlesQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedUninstallBundlesQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedUninstallBundlesQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_BUNDLE_INSTALL_POLICY);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_uninstall_bundles");
}

/**
 * @tc.name: TestGetDisplayVersionQuery001
 * @tc.desc: Test GetDisplayVersionQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetDisplayVersionQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetDisplayVersionQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDisplayVersionQuery002
 * @tc.desc: Test GetDisplayVersionQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetDisplayVersionQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetDisplayVersionQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_GET_DEVICE_INFO);
    ASSERT_TRUE(queryObj->GetPolicyName() == "get_display_version");
    ASSERT_TRUE(queryObj->GetApiType() == IPlugin::ApiType::SYSTEM);
}

/**
 * @tc.name: TestInactiveUserFreezeQuery001
 * @tc.desc: Test InactiveUserFreezeQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestInactiveUserFreezeQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<InactiveUserFreezeQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestInactiveUserFreezeQuery002
 * @tc.desc: Test InactiveUserFreezeQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestInactiveUserFreezeQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<InactiveUserFreezeQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "inactive_user_freeze");
}

/**
 * @tc.name: TestNTPServerQuery001
 * @tc.desc: Test NTPServerQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestNTPServerQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<NTPServerQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestNTPServerQuery002
 * @tc.desc: Test NTPServerQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestNTPServerQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<NTPServerQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    ASSERT_TRUE(queryObj->GetPolicyName() == "ntp_server");
}

/**
 * @tc.name: TestSnapshotSkipQuery001
 * @tc.desc: Test SnapshotSkipQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestSnapshotSkipQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<SnapshotSkipQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSnapshotSkipQuery002
 * @tc.desc: Test SnapshotSkipQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestSnapshotSkipQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<SnapshotSkipQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "snapshot_skip");
}

/**
 * @tc.name: TestDisallowedSMSQuery001
 * @tc.desc: Test DisallowedSMSQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedSMSQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedSMSQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedSMSQuery002
 * @tc.desc: Test DisallowedSMSQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedSMSQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedSMSQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_sms");
}

/**
 * @tc.name: TestDisallowedMMSQuery001
 * @tc.desc: Test DisallowedMMSQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedMMSQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedMMSQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedMMSQuery002
 * @tc.desc: Test DisallowedMMSQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedMMSQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedMMSQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_mms");
}

#ifdef BACKUP_AND_RESTORE_EDM_ENABLE
/**
 * @tc.name: TestDisableBackupAndRestoreQuery001
 * @tc.desc: Test DisableBackupAndRestoreQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBackupAndRestoreQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableBackupAndRestoreQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisableBackupAndRestoreQuery002
 * @tc.desc: Test DisableBackupAndRestoreQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableBackupAndRestoreQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableBackupAndRestoreQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISABLE_BACKUP_AND_RESTORE);
}
#endif

/**
 * @tc.name: TestDisallowModifyAPNQuery001
 * @tc.desc: Test DisallowModifyAPNQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyAPNQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyAPNQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowModifyAPNQuery002
 * @tc.desc: Test DisallowModifyAPNQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyAPNQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyAPNQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_USER_RESTRICTION);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallow_modify_apn");
}

/**
 * @tc.name: TestIsAppKioskAllowedQuery001
 * @tc.desc: Test IsAppKioskAllowedQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestIsAppKioskAllowedQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<IsAppKioskAllowedQuery>();
    std::string permissionTag;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag) == "");
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_ALLOWED_KIOSK_APPS);
}

/**
 * @tc.name: TestIsAppKioskAllowedQuery002
 * @tc.desc: Test IsAppKioskAllowedQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestIsAppKioskAllowedQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<IsAppKioskAllowedQuery>();
    std::string policyData{"[\"com.example.edmtest\"]"};
    MessageParcel data;
    data.WriteString("com.example.edmtest");
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisallowPowerLongPressQuery001
 * @tc.desc: Test DisallowPowerLongPressQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowPowerLongPressQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowPowerLongPressQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowPowerLongPressQuery002
 * @tc.desc: Test DisallowPowerLongPressQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowPowerLongPressQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowPowerLongPressQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_SET_USER_RESTRICTION);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallow_power_long_press");
}

/**
 * @tc.name: TestDisallowedAirplaneModeQuery001
 * @tc.desc: Test DisallowedAirplaneModeQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedAirplaneModeQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedAirplaneModeQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedAirplaneModeQuery002
 * @tc.desc: Test DisallowedAirplaneModeQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedAirplaneModeQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedAirplaneModeQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_airplane_mode");
}

/**
 * @tc.name: TestDisableSetBiometricsAndScreenLockQuery001
 * @tc.desc: Test DisableSetBiometricsAndScreenLockQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSetBiometricsAndScreenLockQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSetBiometricsAndScreenLockQuery>();
    std::string policyData("false");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(OHOS::system::GetBoolParameter(PERSIST_EDM_SET_BIOMETRICS_AND_SCREENLOCK_DISABLE, false),
        reply.ReadBool());
}

/**
 * @tc.name: TestDisableSetBiometricsAndScreenLockQuery002
 * @tc.desc: Test DisableSetBiometricsAndScreenLockQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSetBiometricsAndScreenLockQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSetBiometricsAndScreenLockQuery>();
    std::string policyData("false");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

#ifdef FEATURE_PC_ONLY
/**
 * @tc.name: TestGetAutoUnlockAfterRebootQuery001
 * @tc.desc: Test GetAutoUnlockAfterRebootQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetAutoUnlockAfterRebootQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetAutoUnlockAfterRebootQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAutoUnlockAfterRebootQuery002
 * @tc.desc: Test GetAutoUnlockAfterRebootQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetAutoUnlockAfterRebootQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetAutoUnlockAfterRebootQuery>();
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetAutoUnlockAfterRebootQuery003
 * @tc.desc: Test GetAutoUnlockAfterRebootQuery GetQueryName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestGetAutoUnlockAfterRebootQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetAutoUnlockAfterRebootQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_SET_AUTO_UNLOCK_AFTER_REBOOT);
}

/**
 * @tc.name: TestDisallowModifyEthernetIpQuery001
 * @tc.desc: Test DisallowModifyEthernetIpQuery QueryPolicy function return false.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyEthernetIpQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyEthernetIpQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisallowModifyEthernetIpQuery002
 * @tc.desc: Test DisallowModifyEthernetIpQuery QueryPolicy function return true.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyEthernetIpQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyEthernetIpQuery>();
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisallowModifyEthernetIpQuery003
 * @tc.desc: Test DisallowModifyEthernetIpQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowModifyEthernetIpQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowModifyEthernetIpQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag) ==
        TEST_PERMISSION_ENTERPRISE_SET_USER_RESTRICTION);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISALLOW_MODIFY_ETHERNET_IP);
}

/**
 * @tc.name: DisableUsbStorageDeviceWriteQuery001
 * @tc.desc: Test DisableUserMtpPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUsbStorageDeviceWriteQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableUsbStorageDeviceWriteQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisableUsbStorageDeviceWriteQuery002
 * @tc.desc: Test DisableUsbStorageDeviceWriteQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableUsbStorageDeviceWriteQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableUsbStorageDeviceWriteQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_usb_storage_device_write");
}

#endif

#ifdef SUDO_EDM_ENABLE
/**
 * @tc.name: DisableSudoQuery001
 * @tc.desc: Test DisableSudoPluginTest::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSudoQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> plugin = std::make_shared<DisableSudoQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag));
    ASSERT_EQ(flag, ERR_OK);
    bool result = false;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}
#endif

/**
 * @tc.name: TestDisallowDistributedTransmissionQuery001
 * @tc.desc: Test DisallowDistributedTransmissionQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowDistributedTransmissionQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowDistributedTransmissionQuery>();
    std::string policyData("false");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = true;
    reply.ReadBool(result);
    ASSERT_TRUE(!result);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionQuery002
 * @tc.desc: Test DisallowDistributedTransmissionQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowDistributedTransmissionQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowDistributedTransmissionQuery>();
    std::string policyData("true");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisableSetDeviceNameQuery001
 * @tc.desc: Test DisableSetDeviceNameQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSetDeviceNameQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSetDeviceNameQuery>();
    std::string policyData("false");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(OHOS::system::GetBoolParameter(PERSIST_EDM_SET_DEVICE_NAME_DISABLE, false),
        reply.ReadBool());
}

/**
 * @tc.name: TestDisableSetDeviceNameQuery002
 * @tc.desc: Test DisableSetDeviceNameQuery::QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisableSetDeviceNameQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisableSetDeviceNameQuery>();
    std::string policyData("false");
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

#ifdef PRIVATE_SPACE_EDM_ENABLE
/**
 * @tc.name: TestDisablePrivateSpaceQuery001
 * @tc.desc: Test DisablePrivateSpaceQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisablePrivateSpaceQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisablePrivateSpaceQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisablePrivateSpaceQuery002
 * @tc.desc: Test DisablePrivateSpaceQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisablePrivateSpaceQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisablePrivateSpaceQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISABLED_PRIVATE_SPACE);
}
#endif

#ifdef NOTIFICATION_EDM_ENABLE
/**
 * @tc.name: TestDisallowedNotificationQuery001
 * @tc.desc: Test DisallowedNotificationQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedNotificationQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedNotificationQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowedNotificationQuery002
 * @tc.desc: Test DisallowedNotificationQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowedNotificationQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowedNotificationQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallowed_notification");
}
#endif

#ifdef NETMANAGER_EXT_EDM_ENABLE
/**
 * @tc.name: TestDisallowVPNQuery001
 * @tc.desc: Test DisallowVPNQuery QueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowVPNQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowVPNQuery>();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowVPNQuery002
 * @tc.desc: Test DisallowVPNQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestDisallowVPNQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<DisallowVPNQuery>();
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == "disallow_vpn");
}
#endif
} // namespace TEST
} // namespace EDM
} // namespace OHOS
