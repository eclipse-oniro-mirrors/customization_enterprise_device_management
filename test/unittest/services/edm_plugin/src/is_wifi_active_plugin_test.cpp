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
#include "is_wifi_active_plugin.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class IsWifiActivePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void IsWifiActivePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void IsWifiActivePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestIsWifiActiveFail
 * @tc.desc: Test IsWifiActivePlugin fail function.
 * @tc.type: FUNC
 */
HWTEST_F(IsWifiActivePluginTest, TestIsWifiActiveFail, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = IsWifiActivePlugin::GetPlugin();
    std::string policyData{"TestIsWifiActive"};
    MessageParcel data;
    MessageParcel reply;
    Utils::ResetTokenTypeAndUid();
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::SetEdmInitialEnv();
}

/**
 * @tc.name: TestIsWifiActiveSuc
 * @tc.desc: Test IsWifiActivePlugin success function.
 * @tc.type: FUNC
 */
HWTEST_F(IsWifiActivePluginTest, TestIsWifiActiveSuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = IsWifiActivePlugin::GetPlugin();
    std::string policyData{"TestIsWifiActive"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS