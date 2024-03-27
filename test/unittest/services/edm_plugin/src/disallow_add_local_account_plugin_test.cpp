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

#include "disallow_add_local_account_plugin_test.h"
#include "disallow_add_local_account_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowAddLocalAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowAddLocalAccountPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowAddLocalAccountPlugin
 * @tc.desc: Test DisallowAddLocalAccountPlugin::OnSetPolicy function and remove policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowAddLocalAccountPluginTest, TestDisallowAddLocalAccountPlugin, TestSize.Level1)
{
    DisallowAddLocalAccountPlugin plugin;
    bool data = true;
    ErrCode ret = plugin.OnSetPolicy(data);
    ASSERT_TRUE(ret == ERR_OK && data);

    string adminName{"testAdminName"};
    bool allowAddLocalAccount = true;
    ret = plugin.OnAdminRemove(adminName, allowAddLocalAccount, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowAddLocalAccountPluginGet
 * @tc.desc: Test DisallowAddLocalAccountPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
    HWTEST_F(DisallowAddLocalAccountPluginTest, TestDisallowAddLocalAccountPluginGet, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowAddLocalAccountPlugin::GetPlugin();
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS