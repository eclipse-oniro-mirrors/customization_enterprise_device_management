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
#include "get_adminprovision_info_plugin.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetAdminProvisionInfoPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetAdminProvisionInfoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void GetAdminProvisionInfoPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: GetAdminProvisionInfoSuc
 * @tc.desc: Test get admin provision info function.
 * @tc.type: FUNC
 */
HWTEST_F(GetAdminProvisionInfoPluginTest, GetAdminProvisionInfoSuc, TestSize.Level1)
{
    GetAdminProvisionInfoPlugin plugin;
    std::string policyValue{"get_adminprovision_info"};
    MessageParcel data;
    MessageParcel reply;
    plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);

    std::string bundle_name = reply.ReadString();
    ASSERT_TRUE(bundle_name == "com.ohos.adminprovisioning");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS