/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <vector>

#include "set_default_data_sim_plugin.h"
#include "core_service_client.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetDefaultDataSimPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetDefaultDataSimPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetDefaultDataSimPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetDefaultDataSimAbnormal
 * @tc.desc: Test SetDefaultDataSimPlugin::OnSetPolicy function fail with negative slotId.
 * @tc.type: FUNC
 */
HWTEST_F(SetDefaultDataSimPluginTest, TestSetDefaultDataSimAbnormal, TestSize.Level1)
{
    SetDefaultDataSimPlugin plugin;
    int32_t simId = -1;
    ErrCode ret = plugin.OnSetPolicy(simId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestSetDefaultDataSimFail
 * @tc.desc: Test SetDefaultDataSimPlugin::OnSetPolicy function fail with invalid slotId.
 * @tc.type: FUNC
 */
HWTEST_F(SetDefaultDataSimPluginTest, TestSetDefaultDataSimFail, TestSize.Level1)
{
    SetDefaultDataSimPlugin plugin;
    int32_t simId = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();
    ErrCode ret = plugin.OnSetPolicy(simId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestSetDefaultDataSimSuc
 * @tc.desc: Test SetDefaultDataSimPlugin::OnSetPolicy function success.
 * @tc.type: FUNC
 */
HWTEST_F(SetDefaultDataSimPluginTest, TestSetDefaultDataSimSuc, TestSize.Level1)
{
    SetDefaultDataSimPlugin plugin;
    int32_t simId = 0;
    ErrCode ret = plugin.OnSetPolicy(simId);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SET_DEFAULT_DATA_SIM_FAILED);
}

/**
 * @tc.name: TestGetDefaultDataSim
 * @tc.desc: Test SetDefaultDataSimPlugin::OnGetPolicy function success with slot 1.
 * @tc.type: FUNC
 */
HWTEST_F(SetDefaultDataSimPluginTest, TestGetDefaultDataSim, TestSize.Level1)
{
    SetDefaultDataSimPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, 100);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
