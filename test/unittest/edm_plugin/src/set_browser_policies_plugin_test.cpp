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

#include "set_browser_policies_plugin_test.h"
#include "map_string_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_APP_ID = "test_app_id";
const std::string TEST_APP_ID_1 = "test_app_id_1";
const std::string TEST_POLICIES = "test_policies";
void SetBrowserPoliciesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetBrowserPoliciesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicy when policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    std::map<std::string, std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(policies, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyValueEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicy when policies value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicyValueEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(TEST_APP_ID, ""));
    std::map<std::string, std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(policies, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentData.count(TEST_APP_ID) == 0);
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel reply;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(TEST_APP_ID, TEST_POLICIES));
    std::map<std::string, std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(policies, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(currentData.count(TEST_APP_ID) == 1);
    ASSERT_TRUE(currentData[TEST_APP_ID] == TEST_POLICIES);
}

/**
 * @tc.name: TestOnSetPolicyDonePolicyChanged
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicyDone when isGlobalChanged is true.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicyDonePolicyChanged, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    bool isGlobalChanged = true;
    plugin.OnSetPolicyDone(isGlobalChanged);
    ASSERT_TRUE(isGlobalChanged);
}

/**
 * @tc.name: TestOnSetPolicyDonePolicyUnchanged
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicyDone when isGlobalChanged is false.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicyDonePolicyUnchanged, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    bool isGlobalChanged = false;
    plugin.OnSetPolicyDone(isGlobalChanged);
    ASSERT_FALSE(isGlobalChanged);
}

/**
 * @tc.name: TestOnGetPolicyAppIdEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnGetPolicy when appId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnGetPolicyAppIdEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(TEST_APP_ID, TEST_POLICIES));
    std::string jsonString;
    MapStringSerializer::GetInstance()->Serialize(policies, jsonString);
    std::map<std::string, std::string> currentData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_APP_ID_1);
    plugin.OnGetPolicy(jsonString, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadString().empty());
}

/**
 * @tc.name: TestOnGetPolicySuc
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnGetPolicySuc, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    std::map<std::string, std::string> policies;
    policies.insert(std::make_pair(TEST_APP_ID, TEST_POLICIES));
    std::string jsonString;
    MapStringSerializer::GetInstance()->Serialize(policies, jsonString);
    std::map<std::string, std::string> currentData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(TEST_APP_ID);
    plugin.OnGetPolicy(jsonString, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadString() == TEST_POLICIES);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS