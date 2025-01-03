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

#include "allowed_bluetooth_devices_query.h"
#include "allowed_usb_devices_query.h"
#include "clipboard_policy.h"
#include "clipboard_policy_query.h"
#include "clipboard_policy_serializer.h"
#include "disable_bluetooth_query.h"
#include "disable_camera_query.h"
#include "disable_hdc_query.h"
#include "disable_microphone_query.h"
#include "disable_printer_query.h"
#include "disable_usb_query.h"
#include "disallow_add_local_account_query.h"
#include "disallow_modify_datetime_query.h"
#include "disallowed_install_bundles_query.h"
#include "disallowed_running_bundles_query.h"
#include "disallowed_tethering_query.h"
#include "disallowed_uninstall_bundles_query.h"
#include "edm_constants.h"
#include "fingerprint_auth_query.h"
#include "get_device_encryption_status_query.h"
#include "get_display_version_query.h"
#include "get_security_patch_tag_query.h"
#include "inactive_user_freeze_query.h"
#include "location_policy_query.h"
#include "ntp_server_query.h"
#include "parameters.h"
#include "password_policy.h"
#include "password_policy_query.h"
#include "password_policy_serializer.h"
#include "set_wifi_disabled_query.h"
#include "snapshot_skip_query.h"
#include "usb_read_only_query.h"

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
const std::string POLICY_DATA = "[{\"tokenId\":1,\"clipboardPolicy\":1},{\"tokenId\":2,\"clipboardPolicy\":2}]";
const std::string TEST_VALUE_COMPLEXITYREG = "^(?=.*[a-zA-Z]).{1,9}$";
const int TEST_VALUE_VALIDITY_PERIOD = 2;
const std::string TEST_VALUE_ADDITIONAL_DESCRIPTION = "testDescription";
const std::string TEST_POLICY_DATA =
    "{\"complexityReg\":\"^(?=.*[a-zA-Z]).{1,9}$\", \"validityPeriod\": 2,"
    "\"additionalDescription\": \"testDescription\"}";
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
 * @tc.name: TestClipboardPolicyQuery
 * @tc.desc: Test ClipboardPolicyQuery::QueryPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(PluginPolicyQueryTest, TestClipboardPolicyQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<ClipboardPolicyQuery>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = POLICY_DATA;
    queryObj->QueryPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardPolicy> policyMap;
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
    data.WriteInt32(1);
    queryObj->QueryPolicy(policyData, data, reply, 0);
    int32_t ret = reply.ReadInt32();
    std::string policy = reply.ReadString();
    std::map<int32_t, ClipboardPolicy> policyMap;
    auto serializer = ClipboardSerializer::GetInstance();
    serializer->Deserialize(policy, policyMap);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyMap[1] == ClipboardPolicy::IN_APP);
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
    ASSERT_EQ(OHOS::system::GetBoolParameter(DisableBluetoothQuery::PERSIST_BLUETOOTH_CONTROL, false),
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
    ASSERT_EQ(OHOS::system::GetBoolParameter(DisableBluetoothQuery::PERSIST_BLUETOOTH_CONTROL, false),
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

} // namespace TEST
} // namespace EDM
} // namespace OHOS
