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

#include "uninstall_plugin_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void UninstallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UninstallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test UninstallPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(UninstallPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    UninstallPlugin plugin;
    UninstallParam param = { "testBundle", DEFAULT_USER_ID, false};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS