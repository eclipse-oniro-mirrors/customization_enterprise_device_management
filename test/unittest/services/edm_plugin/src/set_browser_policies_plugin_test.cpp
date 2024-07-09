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
#include "edm_constants.h"
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
const std::string TEST_POLICY_DATA1 = "{\"test_app_id\": \"{\\\"test_policy_name\\\":\\\"test_policy_value\\\"}\"}";
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
 * @tc.name: TestSetPoliciesEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnHandlePolicy when type is SET_POLICIES_TYPE
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPoliciesEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userid = 0;
    data.WriteInt32(EdmConstants::SET_POLICIES_TYPE);
    std::vector<std::string> key;
    std::vector<std::string> value;
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetPoliciesValueEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnHandlePolicy when type is SET_POLICIES_TYPE
 * and policies value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPoliciesValueEmpty, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userid = 0;
    data.WriteInt32(EdmConstants::SET_POLICIES_TYPE);
    std::vector<std::string> key{TEST_APP_ID};
    std::vector<std::string> value{""};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(policyData.policyData == "");
}

/**
 * @tc.name: TestSetPoliciesSuc
 * @tc.desc: Test SetBrowserPoliciesPlugin::OnHandlePolicy when type is SET_POLICIES_TYPE.
 * @tc.type: FUNC
 */
HWTEST_F(SetBrowserPoliciesPluginTest, TestSetPoliciesSuc, TestSize.Level1)
{
    SetBrowserPoliciesPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    int32_t userid = 0;
    data.WriteInt32(EdmConstants::SET_POLICIES_TYPE);
    std::vector<std::string> key{TEST_APP_ID};
    std::vector<std::string> value{TEST_POLICIES};
    data.WriteStringVector(key);
    data.WriteStringVector(value);
    ErrCode ret = plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    ASSERT_TRUE(ret == ERR_OK);
    auto serializer_ = MapStringSerializer::GetInstance();
    std::map<std::string, std::string> currentData;
    serializer_ ->Deserialize(policyData.policyData, currentData);
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

/**
 * @tc.name: TestSetPolicyEmpty
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy when type is SET_POLICY_TYPE
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
    data1.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    data1.WriteStringVector(params1);
    
    ErrCode ret1 = plugin.OnHandlePolicy(0, data1, reply, policyData, userid);
    ASSERT_TRUE(ret1 == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestSetPolicy
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy when type is SET_POLICY_TYPE
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
    data.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    data.WriteStringVector(params);

    auto serializer_ = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer_->Deserialize(policyData.policyData, policies);
    cJSON* beforeParsedPolicy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    cJSON* policy;
    serializer_->Deserialize(cJSON_GetStringValue(beforeParsedPolicy), policy);
    cJSON* policyValue =  cJSON_GetObjectItem(policy, TEST_POLICY_NAME.c_str());
    char *cJsonstr = cJSON_Print(policyValue);
    std::string testStr;
    if (cJsonstr != nullptr) {
        testStr = std::string(cJsonstr);
        cJSON_free(cJsonstr);
    }
    ASSERT_TRUE(testStr == TEST_POLICY_VALUE2);
    cJSON_Delete(policies);
    cJSON_Delete(policy);
}

/**
 * @tc.name: TestSetPolicyEmptyValue
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy when type is SET_POLICY_TYPE
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
    data.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    data.WriteStringVector(params);

    auto serializer_ = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer_->Deserialize(policyData.policyData, policies);
    cJSON* beforeParsedPolicy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    cJSON* policy;
    serializer_->Deserialize(cJSON_GetStringValue(beforeParsedPolicy), policy);
    cJSON* policyValue =  cJSON_GetObjectItem(policy, TEST_POLICY_NAME.c_str());
    ASSERT_TRUE(policyValue == nullptr);
    cJSON_Delete(policies);
    cJSON_Delete(policy);
}

/**
 * @tc.name: TestSetPolicyRoot
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy when type is SET_POLICY_TYPE
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
    data.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    data.WriteStringVector(params);

    auto serializer_ = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer_->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    ASSERT_TRUE(cJSON_GetStringValue(policy) == TEST_POLICY_VALUE2);
    cJSON_Delete(policies);
}

/**
 * @tc.name: TestSetPolicyRootEmptyValue
 * @tc.desc: Test SetBrowserPoliciesPlugin::onHandlePolicy when type is SET_POLICY_TYPE
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
    data.WriteInt32(EdmConstants::SET_POLICY_TYPE);
    data.WriteStringVector(params);

    auto serializer_ = CjsonSerializer::GetInstance();

    HandlePolicyData policyData;
    policyData.policyData = TEST_POLICY_DATA1;
    plugin.OnHandlePolicy(0, data, reply, policyData, userid);
    cJSON* policies;
    serializer_->Deserialize(policyData.policyData, policies);
    cJSON* policy = cJSON_GetObjectItem(policies, TEST_APP_ID.c_str());
    ASSERT_TRUE(policy == nullptr);
    cJSON_Delete(policies);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS