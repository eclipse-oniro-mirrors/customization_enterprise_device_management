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

#include "cjson_serializer.h"
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
const std::string TEST_POLICY_NAME = "test_policy_name";
const std::string TEST_POLICY_VALUE = "\"test_policy_value\"";
const std::string TEST_POLICY_VALUE2 = "\"test_policy_value2\"";
const std::string TEST_POLICY_DATA1 = "{\"test_app_id\": {\"test_policy_name\":\"test_policy_value\"}}";
const std::string TEST_ADMIN_NAME1 = "testAdminName1";
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
 * @tc.name: TestOnSetPolicyDonePolicyChanged
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnSetPolicyDone when isGlobalChanged is true.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestOnSetPolicyDonePolicyChanged, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    std::string adminName = "";
    int32_t userId = 0;
    bool isGlobalChanged = true;
    plugin.OnHandlePolicyDone(0, adminName, isGlobalChanged, userId);
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
    std::string adminName = "";
    int32_t userId = 0;
    bool isGlobalChanged = false;
    plugin.OnHandlePolicyDone(0, adminName, isGlobalChanged, userId);
    ASSERT_FALSE(isGlobalChanged);
}

/**
 * @tc.name: TestSetPolicyEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy
 * and param is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPolicyEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data1;
    MessageParcel data2;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userid = 0;
    std::vector<std::string> params1{"", TEST_POLICY_NAME, TEST_POLICY_VALUE};
    data1.WriteStringVector(params1);

    ErrCode ret1 = plugin.OnHandlePolicy(0, data1, reply, policyData, userid);
    ASSERT_TRUE(ret1 == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetPolicy
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy
 * and normal conditions.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPolicy, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    int32_t userid = 0;
    std::vector<std::string> params{TEST_APP_ID, TEST_POLICY_NAME, TEST_POLICY_VALUE2};
    data.WriteStringVector(params);

    auto serializer = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    cJSON* policyValue =  cJSON_GetObjectItem(policy, TEST_POLICY_NAME.c_str());
    std::string testStr;
    serializer->Serialize(policyValue, testStr);
    ASSERT_TRUE(testStr == TEST_POLICY_VALUE2);
    cJSON_Delete(policies);
}

/**
 * @tc.name: TestSetPolicyEmptyValue
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy
 * and empty policyValue.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPolicyEmptyValue, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    int32_t userid = 0;

    std::vector<std::string> params{TEST_APP_ID, TEST_POLICY_NAME, ""};
    data.WriteStringVector(params);

    auto serializer = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    cJSON* policyValue =  cJSON_GetObjectItem(policy, TEST_POLICY_NAME.c_str());
    ASSERT_TRUE(policyValue == nullptr);
    cJSON_Delete(policies);
}

/**
 * @tc.name: TestSetPolicyRoot
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy
 * and policyName is root.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPolicyRoot, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    int32_t userid = 0;
    std::vector<std::string> params{TEST_APP_ID, "", TEST_POLICY_VALUE2};
    data.WriteStringVector(params);

    auto serializer = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    std::string policyValue;
    serializer->Serialize(policy, policyValue);
    ASSERT_TRUE(policyValue == TEST_POLICY_VALUE2);
    cJSON_Delete(policies);
}

/**
 * @tc.name: TestSetPolicyRootEmptyValue
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy
 * and policyName is root with empty policyValue.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPolicyRootEmptyValue, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    int32_t userid = 0;
    std::vector<std::string> params{TEST_APP_ID, "", ""};
    data.WriteStringVector(params);

    auto serializer = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    ASSERT_TRUE(policy == nullptr);
    cJSON_Delete(policies);
}

/**
 * @tc.name: TestMergePolicyData
 * @tc.desc: Test SetBrowserPoliciesPlugin::MergePolicyData
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestMergePolicyData, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    std::string adminName = TEST_ADMIN_NAME1;
    std::string policyData = TEST_POLICY_DATA1;
    int32_t userId100 = 100;
    auto ret = plugin.GetOthersMergePolicyData(adminName, userId100, policyData);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddBrowserPoliciesToRootEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::AddBrowserPoliciesToRoot when policiesString is empty
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestAddBrowserPoliciesToRootEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    cJSON* root = cJSON_CreateObject();
    std::string policiesString;
    auto ret = plugin.AddBrowserPoliciesToRoot(root, policiesString);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: TestAddBrowserPoliciesToRootParseError
 * @tc.desc: Test SetBrowserPoliciesPlugin::AddBrowserPoliciesToRoot when policiesString is parsed error
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestAddBrowserPoliciesToRootParseError, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    cJSON* root = cJSON_CreateObject();
    std::string policiesString = "{";
    auto ret = plugin.AddBrowserPoliciesToRoot(root, policiesString);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: TestAddBrowserPoliciesToRoot
 * @tc.desc: Test SetBrowserPoliciesPlugin::AddBrowserPoliciesToRoot
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestAddBrowserPoliciesToRoot, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, TEST_APP_ID.c_str(), cJSON_CreateObject());
    std::string policiesString = TEST_POLICY_DATA1;
    auto ret = plugin.AddBrowserPoliciesToRoot(root, policiesString);
    ASSERT_TRUE(ret);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS