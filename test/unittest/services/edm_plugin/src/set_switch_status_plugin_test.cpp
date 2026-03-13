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
#include "edm_ipc_interface_code.h"
#include "set_switch_status_plugin.h"
#include "utils.h"
#include "edm_log.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetSwitchStatusPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
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

/**
 * @tc.name: TestOnSetBluetoothStatusSuccess
 * @tc.desc: Test SetSwitchStatusPluginTest::OnSetPolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(SetSwitchStatusPluginTest, TestOnSetBluetoothStatusSuccess, TestSize.Level1)
{
    SetSwitchStatusPlugin plugin;
    SwitchParam param{SwitchKey::BLUETOOTH, SwitchStatus::OFF};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    param.status = SwitchStatus::ON;
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
    SwitchParam param{SwitchKey::WIFI, SwitchStatus::OFF};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    param.status = SwitchStatus::ON;
    ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS