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
#include <vector>

#include "active_sim_plugin.h"
#include "core_service_client.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class ActiveSimPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void ActiveSimPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ActiveSimPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestActiveSimAbnormal
 * @tc.desc: Test ActiveSimPluginTest::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimAbnormal, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = -1;
    ErrCode ret = plugin.OnSetPolicy(slotId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestActiveSimFail
 * @tc.desc: Test ActiveSimPluginTest::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimFail, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();
    ErrCode ret = plugin.OnSetPolicy(slotId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestActiveSimSuc
 * @tc.desc: Test ActiveSimPluginTest::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimSuc, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = 0;
    ErrCode ret = plugin.OnSetPolicy(slotId);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestActiveSimRemoveAbnormal
 * @tc.desc: Test ActiveSimPluginTest::OnRemovePolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimRemoveAbnormal, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = -1;
    ErrCode ret = plugin.OnRemovePolicy(slotId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestActiveSimRemoveFail
 * @tc.desc: Test ActiveSimPluginTest::OnRemovePolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimRemoveFail, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();
    ErrCode ret = plugin.OnRemovePolicy(slotId);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestActiveSimRemoveSuc
 * @tc.desc: Test ActiveSimPluginTest::OnRemovePolicy function suc.
 * @tc.type: FUNC
 */
HWTEST_F(ActiveSimPluginTest, TestActiveSimRemoveSuc, TestSize.Level1)
{
    ActiveSimPlugin plugin;
    int32_t slotId = 0;
    ErrCode ret = plugin.OnRemovePolicy(slotId);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS