/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "system_service_start_handler.h"
#include "utils.h"
 
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string testBundle = "com.edm.testDemo";
class SystemServiceStartHandlerTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SystemServiceStartHandlerTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SystemServiceStartHandlerTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: OnNetPolicyManagerStartTest
 * @tc.desc: Test SystemServiceStartHandlerTest::OnNetPolicyManagerStartTest function.
 * @tc.type: FUNC
 */
HWTEST_F(SystemServiceStartHandlerTest, OnNetPolicyManagerStartTest, TestSize.Level1)
{
    bool ret = SystemServiceStartHandler::GetInstance()->OnNetPolicyManagerStart();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: AddNetworkAccessPolicyTest
 * @tc.desc: Test SystemServiceStartHandlerTest::AddNetworkAccessPolicyTest function.
 * @tc.type: FUNC
 */
HWTEST_F(SystemServiceStartHandlerTest, AddNetworkAccessPolicyTest, TestSize.Level1)
{
    bool ret = SystemServiceStartHandler::GetInstance()->AddNetworkAccessPolicy({testBundle});
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: RemoveNetworkAccessPolicyTest
 * @tc.desc: Test SystemServiceStartHandlerTest::RemoveNetworkAccessPolicyTest function.
 * @tc.type: FUNC
 */
HWTEST_F(SystemServiceStartHandlerTest, RemoveNetworkAccessPolicyTest, TestSize.Level1)
{
    bool ret = SystemServiceStartHandler::GetInstance()->RemoveNetworkAccessPolicy({testBundle});
    ASSERT_TRUE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS