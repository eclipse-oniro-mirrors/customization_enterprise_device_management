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

#include "allowed_notification_bundles_plugin_test.h"
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
void AllowedNotificationBundlesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedNotificationBundlesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicyEmpty
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyEmpty, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithInvalidUserId
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function when userId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithInvalidUserId, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 0;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithEmptyTrustList
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function when trustList is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithEmptyTrustList, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithMultipleData
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function when data size > 1.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithMultipleData, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles1;
    bundles1.userId = 100;
    bundles1.trustList.insert("com.example.test1");
    data.push_back(bundles1);
    AllowedNotificationBundlesType bundles2;
    bundles2.userId = 101;
    bundles2.trustList.insert("com.example.test2");
    data.push_back(bundles2);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnSetPolicyWithValidData
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithValidData, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithDuplicateData
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function with duplicate data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithDuplicateData, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    bundles.trustList.insert("com.example.test1");
    bundles.trustList.insert("com.example.test2");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    AllowedNotificationBundlesType existingBundles;
    existingBundles.userId = 100;
    existingBundles.trustList.insert("com.example.test1");
    currentData.push_back(existingBundles);
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyWithTooManyBundles
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnSetPolicy function when trustList exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnSetPolicyWithTooManyBundles, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    for (int i = 0; i < 201; i++) {
        bundles.trustList.insert("com.example.test" + std::to_string(i));
    }
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyEmpty
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyEmpty, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithInvalidUserId
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function when userId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyWithInvalidUserId, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = -1;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithEmptyTrustList
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function when trustList is empty.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyWithEmptyTrustList, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnRemovePolicyWithValidData
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyWithValidData, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    AllowedNotificationBundlesType existingBundles;
    existingBundles.userId = 100;
    existingBundles.trustList.insert("com.example.test");
    existingBundles.trustList.insert("com.example.test2");
    currentData.push_back(existingBundles);
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyWithNonExistingUser
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function when user does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyWithNonExistingUser, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    AllowedNotificationBundlesType existingBundles;
    existingBundles.userId = 101;
    existingBundles.trustList.insert("com.example.test2");
    currentData.push_back(existingBundles);
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyClearAllBundles
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnRemovePolicy function when all bundles are removed.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnRemovePolicyClearAllBundles, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::vector<AllowedNotificationBundlesType> data;
    AllowedNotificationBundlesType bundles;
    bundles.userId = 100;
    bundles.trustList.insert("com.example.test");
    data.push_back(bundles);
    std::vector<AllowedNotificationBundlesType> currentData;
    AllowedNotificationBundlesType existingBundles;
    existingBundles.userId = 100;
    existingBundles.trustList.insert("com.example.test");
    currentData.push_back(existingBundles);
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemove
 * @tc.desc: Test AllowedNotificationBundlesPlugin::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedNotificationBundlesPluginTest, TestOnAdminRemove, TestSize.Level1)
{
    AllowedNotificationBundlesPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<AllowedNotificationBundlesType> data;
    std::vector<AllowedNotificationBundlesType> mergeData;
    ErrCode ret = plugin.OnAdminRemove(adminName, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
