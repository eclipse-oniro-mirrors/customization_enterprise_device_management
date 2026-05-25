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

#include "get_application_window_states_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"
#include "window_state_info.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetApplicationWindowStatesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetApplicationWindowStatesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetApplicationWindowStatesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test GetApplicationWindowStatesPlugin::OnGetPolicy with uninstall app.
 * @tc.type: FUNC
 */
HWTEST_F(GetApplicationWindowStatesPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::string bundleName = "com.test.app";
    int32_t appIndex = 0;

    data.WriteString(bundleName);
    data.WriteInt32(appIndex);
    std::vector<WindowStateInfo> windowStateInfos;
    GetApplicationWindowStatesPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFail
 * @tc.desc: Test GetApplicationWindowStatesPlugin::OnGetPolicy with invalid bundlename.
 * @tc.type: FUNC
 */
HWTEST_F(GetApplicationWindowStatesPluginTest, TestOnGetPolicyFail, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;

    data.WriteString("");
    data.WriteInt32(0);
    std::vector<WindowStateInfo> windowStateInfos;
    GetApplicationWindowStatesPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS