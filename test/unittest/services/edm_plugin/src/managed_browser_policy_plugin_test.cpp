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

#include <cstdio>
#include <fstream>
#include "managed_browser_policy_plugin_test.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "managed_browser_policy_serializer.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"test_bundle_name\":{\"version\":1,\"policyNames\":[\"test_policy_name\"]}}";
const std::string TEST_BUNDLE_NAME = "test_bundle_name";
const std::string TEST_POLICY_NAME = "test_policy_name";
const std::string TEST_POLICY_VALUE = "\"test_policy_value\"";
const char* const MANAGED_BROWSER_POLICY_DIR = "/data/service/el1/public/edm/browser/";
const char* const MANAGED_BROWSER_POLICY_SUFFIX = ".dat";
const std::string URL = MANAGED_BROWSER_POLICY_DIR + TEST_BUNDLE_NAME + MANAGED_BROWSER_POLICY_SUFFIX;
void ManagedBrowserPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManagedBrowserPolicyPluginTest::TearDownTestSuite(void)
{
    ASSERT_TRUE(remove(URL.c_str()) == ERR_OK);
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy when BundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyBundleName;
    MessageParcel data;
    data.WriteString(emptyBundleName);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithEmptyPolicyName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy when PolicyName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicyFailWithEmptyPolicyName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyPolicyName;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(emptyPolicyName);
    data.WriteString(TEST_POLICY_VALUE);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicySucForAddPolicy
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy Success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicySucAddPolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(TEST_POLICY_VALUE);
    MessageParcel reply;
    HandlePolicyData policyData;
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicyFailWithInvalidType
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy when type is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicyFailWithInvalidType, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::string policyData;
    std::string type = "invalidType";
    MessageParcel data;
    data.WriteString(type);
    MessageParcel reply;

    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicyFailWithEmptyBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy with empty bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicyFailWithEmptyBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::string policyData;
    std::string type = EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA;
    std::string bundleName;
    MessageParcel data;
    data.WriteString(type);
    data.WriteString(bundleName);
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicySucForGetPolicyData
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnGetPolicy success for get policy data.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnGetPolicySucForGetPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel data;
    data.WriteString(EdmConstants::Browser::GET_MANAGED_BROWSER_FILE_DATA);
    data.WriteString(TEST_BUNDLE_NAME);
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() > 0);
}

/**
 * @tc.name: TestGetManagedBrowserPolicyVersionSuc
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::GetManagedBrowserPolicyVersion success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetManagedBrowserPolicyVersionSuc, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;
    std::string policyData = TEST_POLICY_DATA;
    ErrCode ret = plugin.GetManagedBrowserPolicyVersion(policyData, TEST_BUNDLE_NAME, reply);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == 1);
}

/**
 * @tc.name: TestGetSelfManagedBrowserPolicyData
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::GetManagedBrowserPolicyFileData success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestGetSelfManagedBrowserPolicyData, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    MessageParcel reply;

    ErrCode ret = plugin.GetManagedBrowserPolicyFileData(TEST_BUNDLE_NAME, reply);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() > 0);
}

/**
 * @tc.name: TestOnHandlePolicySucForModifyOrRemovePolicy
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::OnHandlePolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestOnHandlePolicySucForModifyOrRemovePolicy, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::uint32_t funcCode = 0;
    std::string emptyPolicyValue;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteString(TEST_POLICY_NAME);
    data.WriteString(emptyPolicyValue);
    MessageParcel reply;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    policies[TEST_BUNDLE_NAME].version = 1;
    policies[TEST_BUNDLE_NAME].policyNames.push_back(TEST_POLICY_NAME);
    HandlePolicyData policyData;
    auto serializer = ManagedBrowserPolicySerializer::GetInstance();
    serializer->Serialize(policies, policyData.policyData);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidUrl
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::ModifyOrRemoveManagedBrowserPolicy failed with invalid url.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidUrl, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    const std::string bundleName = "com.not.existed";
    const std::string policyName;
    const std::string policyValue;
    ErrCode ret = plugin.ModifyOrRemoveManagedBrowserPolicy(policies, bundleName, policyName, policyValue);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidFile
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::ModifyOrRemoveManagedBrowserPolicy failed with invalid bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestModifyOrRemoveManagedBrowserPolicyFailWithInvalidFile, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    const std::string bundleName = TEST_BUNDLE_NAME;
    std::ofstream policyFile(URL, std::ios::app);
    if (policyFile.fail()) {
        ASSERT_TRUE(false);
    }
    policyFile << "test" << std::endl;
    policyFile.close();
    ErrCode ret = plugin.ModifyOrRemoveManagedBrowserPolicy(policies, bundleName, TEST_POLICY_NAME, TEST_POLICY_VALUE);
    std::string tempUrl = MANAGED_BROWSER_POLICY_DIR + bundleName + "_tmp" + MANAGED_BROWSER_POLICY_SUFFIX;
    ASSERT_TRUE(remove(URL.c_str()) == ERR_OK);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestAddManagedBrowserPolicyFailWithInvalidBundleName
 * @tc.desc: Test ManagedBrowserPolicyPluginTest::AddManagedBrowserPolicy failed with invalid bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(ManagedBrowserPolicyPluginTest, TestAddManagedBrowserPolicyFailWithInvalidBundleName, TestSize.Level1)
{
    ManagedBrowserPolicyPlugin plugin;
    std::map<std::string, ManagedBrowserPolicyType> policies;
    const std::string bundleName = "com.invalid../../";
    ErrCode ret = plugin.AddManagedBrowserPolicy(policies, bundleName, TEST_POLICY_NAME, TEST_POLICY_VALUE);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS