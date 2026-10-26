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

#include "os_account_manager.h"
#include "parameters.h"

#define private public
#include "iedm_bluetooth_manager.h"
#undef private

#include "edm_bluetooth_manager_impl.h"
#include "edm_bluetooth_manager_mock.h"
#include "edm_ipc_interface_code.h"
#include "set_switch_status_plugin.h"
#include "utils.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string MDM_BLUETOOTH_PROP = "persist.edm.prohibit_bluetooth";
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
const std::string PARAM_FORCE_ENABLE_BLUETOOTH = "persist.edm.force_enable_bluetooth";
#ifdef NFC_EDM_ENABLE
const std::string PARAM_FORCE_ENABLE_NFC = "persist.edm.force_enable_nfc";
const std::string PARAM_EDM_NFC_DISABLE = "persist.edm.nfc_disable";
#endif
class SetSwitchStatusPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EdmBluetoothManagerMock> bluetoothManagerMock_ = std::make_shared<EdmBluetoothManagerMock>();
};

void SetSwitchStatusPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetSwitchStatusPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void SetSwitchStatusPluginTest::SetUp()
{
    IEdmBluetoothManager::iInstance_ = bluetoothManagerMock_.get();
}

void SetSwitchStatusPluginTest::TearDown()
{
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
    system::SetParameter(MDM_WIFI_PROP, "false");
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
#ifdef NFC_EDM_ENABLE
    system::SetParameter(PARAM_FORCE_ENABLE_NFC, "false");
    system::SetParameter(PARAM_EDM_NFC_DISABLE, "false");
#endif
    bluetoothManagerMock_.reset();
}

/**
 * @tc.name: TestOnSetBluetoothStatusSuccess
 * @tc.desc: Test SetSwitchStatusPluginTest::OnSetPolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnSetBluetoothStatusSuccess, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::vector<SwitchParam> param;
    SwitchParam paramItem{SwitchKey::BLUETOOTH, SwitchStatus::OFF};
    param.push_back(paramItem);
    MessageParcel reply;
    EXPECT_CALL(*bluetoothManagerMock_, DisableBt).WillOnce(DoAll(Return(true)));
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    param[0].status = SwitchStatus::ON;
    EXPECT_CALL(*bluetoothManagerMock_, EnableBle).WillOnce(DoAll(Return(true)));
    ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    param[0].status = SwitchStatus::FORCE_ON;
    EXPECT_CALL(*bluetoothManagerMock_, EnableBle).WillOnce(DoAll(Return(true)));
    ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: OnSetWifiStatusSuccess
 * @tc.desc: Test SetSwitchStatusPluginTest::OnSetPolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, OnSetWifiStatusSuccess, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::vector<SwitchParam> param;
    SwitchParam paramItem{SwitchKey::WIFI, SwitchStatus::OFF};
    param.push_back(paramItem);
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    param[0].status = SwitchStatus::ON;
    ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveSuccess
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove when there are multiple admins
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveSuccess, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::BLUETOOTH, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveBluetooth
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove for Bluetooth switch
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveBluetooth, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::BLUETOOTH, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveWifi
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove for WiFi switch
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveWifi, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::WIFI, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveNFC
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove for NFC switch
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveNFC, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::NFC, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveUnknownKey
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove with unknown switch key
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveUnknownKey, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::UNKNOWN, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveNearlink
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove for Nearlink switch (default case)
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveNearlink, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    dataVec.push_back({SwitchKey::NEARLINK, SwitchStatus::FORCE_ON});
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyEmptyParam
 * @tc.desc: Test SetSwitchStatusPlugin::OnSetPolicy with empty parameter vector
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnSetPolicyEmptyParam, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::vector<SwitchParam> param;
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicyInvalidKeySmall
 * @tc.desc: Test OnGetPolicy with switch key below valid range.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetPolicyInvalidKeySmall, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    data.WriteInt32(-1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicyInvalidKeyLarge
 * @tc.desc: Test OnGetPolicy with switch key above valid range.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetPolicyInvalidKeyLarge, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::NFC) + 1);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicyNearlinkDefault
 * @tc.desc: Test OnGetPolicy with Nearlink key falls to default case.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetPolicyNearlinkDefault, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::NEARLINK));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}

/**
 * @tc.name: TestOnGetPolicyBluetoothForceOn
 * @tc.desc: Test OnGetPolicy with Bluetooth key when force enabled.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetPolicyBluetoothForceOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "true");
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::BLUETOOTH));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(SwitchStatus::FORCE_ON));
}

/**
 * @tc.name: TestOnGetPolicyWifiForceOn
 * @tc.desc: Test OnGetPolicy with WiFi key when force enabled.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetPolicyWifiForceOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_WIFI_PROP, "false");
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "true");
    MessageParcel data;
    MessageParcel reply;
    std::string policyData;
    data.WriteInt32(static_cast<int32_t>(SwitchKey::WIFI));
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(SwitchStatus::FORCE_ON));
}

/**
 * @tc.name: TestOnGetBluetoothStatusMdmDisabled
 * @tc.desc: Test OnGetBluetoothStatus when bluetooth disabled by MDM.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetBluetoothStatusMdmDisabled, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "true");
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetBluetoothStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestOnGetBluetoothStatusForceOn
 * @tc.desc: Test OnGetBluetoothStatus when bluetooth force enabled.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetBluetoothStatusForceOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "true");
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetBluetoothStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::FORCE_ON);
}

/**
 * @tc.name: TestOnGetBluetoothStatusGetBtStateFailed
 * @tc.desc: Test OnGetBluetoothStatus when GetBtState returns -1.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetBluetoothStatusGetBtStateFailed, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState).WillOnce(Return(-1));
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetBluetoothStatus(status);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestOnGetBluetoothStatusTurnOn
 * @tc.desc: Test OnGetBluetoothStatus when bluetooth state is TURN_ON.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetBluetoothStatusTurnOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState)
        .WillOnce(Return(static_cast<int32_t>(EdmBluetoothState::TURN_ON)));
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetBluetoothStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::ON);
}

/**
 * @tc.name: TestOnGetBluetoothStatusTurnOff
 * @tc.desc: Test OnGetBluetoothStatus when bluetooth state is TURN_OFF.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetBluetoothStatusTurnOff, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_BLUETOOTH_PROP, "false");
    system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState)
        .WillOnce(Return(static_cast<int32_t>(EdmBluetoothState::TURN_OFF)));
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetBluetoothStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestOnGetWifiStatusMdmDisabled
 * @tc.desc: Test OnGetWifiStatus when wifi disabled by MDM.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetWifiStatusMdmDisabled, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_WIFI_PROP, "true");
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetWifiStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::OFF);
}

/**
 * @tc.name: TestOnGetWifiStatusForceOn
 * @tc.desc: Test OnGetWifiStatus when wifi force enabled.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetWifiStatusForceOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    system::SetParameter(MDM_WIFI_PROP, "false");
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "true");
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetWifiStatus(status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status, SwitchStatus::FORCE_ON);
}

/**
 * @tc.name: TestOnGetNFCStatusUnsupported
 * @tc.desc: Test OnGetNFCStatus when NFC is not supported.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnGetNFCStatusUnsupported, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    SwitchStatus status = SwitchStatus::UNKNOWN;
    ErrCode ret = plugin.OnGetNFCStatus(status);
#ifdef NFC_EDM_ENABLE
    EXPECT_EQ(ret, ERR_OK);
#else
    EXPECT_EQ(ret, EdmReturnErrCode::INTERFACE_UNSUPPORTED);
#endif
}

/**
 * @tc.name: TestOnSetWifiStatusForceOn
 * @tc.desc: Test OnSetPolicy with WiFi FORCE_ON status.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnSetWifiStatusForceOn, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::vector<SwitchParam> param;
    SwitchParam paramItem{SwitchKey::WIFI, SwitchStatus::FORCE_ON};
    param.push_back(paramItem);
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
