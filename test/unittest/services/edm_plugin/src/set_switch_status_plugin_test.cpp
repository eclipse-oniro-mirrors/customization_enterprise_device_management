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

#define private public
#include "iedm_bluetooth_manager.h"
#undef private

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
 * @tc.name: TestOnAdminRemoveEmptyData
 * @tc.desc: Test SetSwitchStatusPlugin::OnAdminRemove with empty data vector
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnAdminRemoveEmptyData, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    std::string adminName = "com.edm.test.admin";
    std::vector<SwitchParam> dataVec;
    std::vector<SwitchParam> mergeData;
    int32_t userId = 100;
    ErrCode ret = plugin.OnAdminRemove(adminName, dataVec, mergeData, userId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
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
} // namespace TEST
} // namespace EDM
} // namespace OHOS
