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

#include "bluetooth_host.h"

#define private public
#include "edm_bluetooth_manager_impl.h"
#undef private
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t INVALID_BLUETOOTH_STATE = -1;

class EdmBluetoothManagerImplTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void EdmBluetoothManagerImplTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void EdmBluetoothManagerImplTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TransformBluetoothStateSuc
 * @tc.desc: Test TransformBluetoothState function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBluetoothManagerImplTest, EnableBle_ReturnFalse, TestSize.Level1)
{
    auto manager = EdmBluetoothManagerImpl::GetInstance();
    manager->GetLocalName();
    manager->GetBtState();
    manager->GetBtConnectionState();
    bool ret = manager->DisableBt();
    EXPECT_EQ(ret, true);
    ret = manager->EnableBle();
    EXPECT_EQ(ret, true);
    ret = manager->DisableBt();
    EXPECT_EQ(ret, true);
    ret = manager->DisableBt();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: TransformBluetoothStateSuc
 * @tc.desc: Test TransformBluetoothState function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBluetoothManagerImplTest, TransformBluetoothStateSuc, TestSize.Level1)
{
    auto manager = EdmBluetoothManagerImpl::GetInstance();
    int32_t realState = manager->TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_ON));
    ASSERT_TRUE(realState == EdmBluetoothState::TURNING_ON);
    realState = manager->TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    ASSERT_TRUE(realState == EdmBluetoothState::TURN_ON);
    realState = manager->TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_OFF));
    ASSERT_TRUE(realState == EdmBluetoothState::TURNING_OFF);
    realState = manager->TransformBluetoothState(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF));
    ASSERT_TRUE(realState == EdmBluetoothState::TURN_OFF);
    realState = manager->TransformBluetoothState(INVALID_BLUETOOTH_STATE);
    ASSERT_TRUE(realState == INVALID_BLUETOOTH_STATE);
}

/**
 * @tc.name: TransformBluetoothConnectionStateSuc
 * @tc.desc: Test TransformBluetoothConnectionState function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmBluetoothManagerImplTest, TransformBluetoothConnectionStateSuc, TestSize.Level1)
{
    auto manager = EdmBluetoothManagerImpl::GetInstance();
    int32_t realConnectionState =
        manager->TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTING));
    ASSERT_TRUE(realConnectionState == EdmBluetoothConnectionState::CONNECTING);
    realConnectionState =
        manager->TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    ASSERT_TRUE(realConnectionState == EdmBluetoothConnectionState::CONNECTED);
    realConnectionState =
        manager->TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTING));
    ASSERT_TRUE(realConnectionState == EdmBluetoothConnectionState::DISCONNECTING);
    realConnectionState =
        manager->TransformBluetoothConnectionState(static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED));
    ASSERT_TRUE(realConnectionState == EdmBluetoothConnectionState::DISCONNECTED);
    realConnectionState =
        manager->TransformBluetoothConnectionState(INVALID_BLUETOOTH_STATE);
    ASSERT_TRUE(realConnectionState == INVALID_BLUETOOTH_STATE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS