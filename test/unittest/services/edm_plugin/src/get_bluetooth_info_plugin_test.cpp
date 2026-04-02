/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
#include "iedm_bluetooth_manager.h"
#undef private

#include "edm_bluetooth_manager_mock.h"
#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "get_bluetooth_info_plugin.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetBluetoothInfoPluginTest : public testing::Test {
public:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);

    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EdmBluetoothManagerMock> bluetoothManagerMock_ = std::make_shared<EdmBluetoothManagerMock>();
};

void GetBluetoothInfoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void GetBluetoothInfoPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

void GetBluetoothInfoPluginTest::SetUp()
{
    IEdmBluetoothManager::iInstance_ = bluetoothManagerMock_.get();
}

void GetBluetoothInfoPluginTest::TearDown()
{
    bluetoothManagerMock_.reset();
}

/**
 * @tc.name: GetBluetoothInfoSuc
 * @tc.desc: Test get bluetooth info function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, GetBluetoothInfoSuc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    std::string policyValue{"GetBluetoothInfo"};
    MessageParcel data;
    MessageParcel reply;

    EXPECT_CALL(*bluetoothManagerMock_, GetLocalName).WillOnce(DoAll(Return("test")));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState).WillOnce(DoAll(Return(-1)));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtConnectionState).WillOnce(DoAll(Return(-1)));

    plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: GetBluetoothInfo_GetState_Suc
 * @tc.desc: Test get bluetooth info function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, GetBluetoothInfo_GetState_Suc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    std::string policyValue{"GetBluetoothInfo"};
    MessageParcel data;
    MessageParcel reply;

    EXPECT_CALL(*bluetoothManagerMock_, GetLocalName).WillOnce(DoAll(Return("")));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState).WillOnce(DoAll(Return(0)));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtConnectionState).WillOnce(DoAll(Return(-1)));

    plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(reply.ReadInt32(), EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: GetBluetoothInfo_GetConnectionState_Suc
 * @tc.desc: Test get bluetooth info function.
 * @tc.type: FUNC
 */
HWTEST_F(GetBluetoothInfoPluginTest, GetBluetoothInfo_GetConnectionState_Suc, TestSize.Level1)
{
    GetBluetoothInfoPlugin plugin;
    std::string policyValue{"GetBluetoothInfo"};
    MessageParcel data;
    MessageParcel reply;

    EXPECT_CALL(*bluetoothManagerMock_, GetLocalName).WillOnce(DoAll(Return("")));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtState).WillOnce(DoAll(Return(0)));
    EXPECT_CALL(*bluetoothManagerMock_, GetBtConnectionState).WillOnce(DoAll(Return(0)));

    plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);

    std::string name = reply.ReadString();
    int state = reply.ReadInt32();
    int connectionState = reply.ReadInt32();
    EXPECT_TRUE(name.empty());
    EXPECT_EQ(state, 0);
    EXPECT_EQ(connectionState, 0);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS