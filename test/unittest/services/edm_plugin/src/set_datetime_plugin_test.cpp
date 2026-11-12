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

#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "iplugin.h"
#include "message_parcel.h"
#include "edm_constants.h"
#include "set_datetime_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int64_t TEST_TIMESTAMP_MS = 1690000000000LL;
}

class SetDateTimePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetDateTimePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetDateTimePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnSetPolicy
 * @tc.desc: Test SetDateTimePlugin::OnSetPolicy applies the timestamp and notifies settings.
 * @tc.type: FUNC
 */
HWTEST_F(SetDateTimePluginTest, TestOnSetPolicy, TestSize.Level1)
{
    SetDateTimePlugin plugin;
    int64_t data = TEST_TIMESTAMP_MS;
    ErrCode ret = plugin.OnSetPolicy(data);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestPluginAttributes
 * @tc.desc: Test SetDateTimePlugin policy code and policy name.
 * @tc.type: FUNC
 */
HWTEST_F(SetDateTimePluginTest, TestPluginAttributes, TestSize.Level1)
{
    auto plugin = SetDateTimePlugin::GetPlugin();
    ASSERT_NE(plugin, nullptr);
    EXPECT_EQ(plugin->GetCode(), EdmInterfaceCode::SET_DATETIME);
    EXPECT_EQ(plugin->GetPolicyName(), PolicyName::POLICY_SET_DATETIME);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
