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
#include "iplugin_template.h"
#include "is_wifi_active_plugin.h"
#include "iplugin_manager.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class IsWifiActivePluginTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestOnPolicy
 * @tc.desc: Test OnPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(IsWifiActivePluginTest, TestIsWifiActive, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = IsWifiActivePlugin::GetPlugin();
    std::string policyData{"TestIsWifiActive"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS