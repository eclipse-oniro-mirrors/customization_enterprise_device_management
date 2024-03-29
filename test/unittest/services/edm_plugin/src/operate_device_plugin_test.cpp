/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "operate_device_plugin.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class OperateDevicePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void OperateDevicePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void OperateDevicePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestLockScreenFail
 * @tc.desc: Test OperateDevicePlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDevicePluginTest, TestLockScreenFail, TestSize.Level1)
{
    OperateDevicePlugin plugin;
    int32_t userId = 0;
    OperateDeviceParam param{EdmConstants::DeviceControl::LOCK_SCREEN, "", userId};
    MessageParcel reply;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    SetSelfTokenID(selfTokenId);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
/**
 * @tc.name: TestLockScreenSuccess
 * @tc.desc: Test OperateDevicePlugin::OnSetPolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDevicePluginTest, TestLockScreenSuccess, TestSize.Level1)
{
    OperateDevicePlugin plugin;
    int32_t userId = 0;
    OperateDeviceParam param{EdmConstants::DeviceControl::LOCK_SCREEN, "", userId};
    MessageParcel reply;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromProcess(userId);
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestShutdown
 * @tc.desc: Test OperateDevicePlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDevicePluginTest, TestShutdown, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    OperateDevicePlugin plugin;
    int32_t userId = 0;
    OperateDeviceParam param{EdmConstants::DeviceControl::SHUT_DOWN, "", userId};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: TestReboot
 * @tc.desc: Test OperateDevicePlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDevicePluginTest, TestReboot, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    OperateDevicePlugin plugin;
    int32_t userId = 0;
    OperateDeviceParam param{EdmConstants::DeviceControl::REBOOT, "", userId};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    SetSelfTokenID(selfTokenId);
}

/**
 * @tc.name: TestResetFactory
 * @tc.desc: Test OperateDevicePlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(OperateDevicePluginTest, TestResetFactory, TestSize.Level1)
{
    uint64_t selfTokenId = GetSelfTokenID();
    SetSelfTokenID(0);
    OperateDevicePlugin plugin;
    int32_t userId = 0;
    OperateDeviceParam param{EdmConstants::DeviceControl::RESET_FACTORY, "", userId};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    SetSelfTokenID(selfTokenId);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
