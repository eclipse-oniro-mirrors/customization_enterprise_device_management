/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "get_security_patch_tag_plugin.h"

#include <gtest/gtest.h>

#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetSecurityPatchTagPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetSecurityPatchTagPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void GetSecurityPatchTagPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: GetSecurityPatchTagSuc
 * @tc.desc: Test get security patch tag function.
 * @tc.type: FUNC
 */
HWTEST_F(GetSecurityPatchTagPluginTest, GetSecurityPatchTagSuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetSecurityPatchTagPlugin::GetPlugin();
    std::string policyValue{"GetSecurityPatchTag"};
    MessageParcel data;
    MessageParcel reply;
    plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadString() != "");
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS