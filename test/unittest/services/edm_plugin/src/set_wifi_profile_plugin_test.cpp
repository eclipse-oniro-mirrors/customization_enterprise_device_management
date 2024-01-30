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
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "set_wifi_profile_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class SetWifiProfilePluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetWifiProfilePluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetWifiProfilePluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetWifiProfile
 * @tc.desc: Test SetWifiProfilePlugin::OnSetPolicy function when it is SYSTEM_ABNORMALLY.
 * @tc.type: FUNC
 */
HWTEST_F(SetWifiProfilePluginTest, TestSetWifiProfile, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    SetWifiProfilePlugin plugin;
    Wifi::WifiDeviceConfig config;
    ErrCode ret = plugin.OnSetPolicy(config);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    Utils::ResetTokenTypeAndUid();
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS