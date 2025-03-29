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

#define protected public
#include "disable_camera_plugin.h"
#undef protected
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class DisableCameraPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisableCameraPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisableCameraPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisableCameraPluginTestGet
 * @tc.desc: Test DisableCameraPluginTest::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisableCameraPluginTest, TestDisableCameraPluginTestGet, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::string policyData = "true";
    DisableCameraPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, 100);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS