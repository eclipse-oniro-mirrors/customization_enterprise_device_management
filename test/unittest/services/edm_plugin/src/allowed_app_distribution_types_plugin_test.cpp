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

#include <gtest/gtest.h>
#include "allowed_app_distribution_types_plugin.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t APP_DISTRIBUTION_TYPE1 = 1;
const int32_t APP_DISTRIBUTION_TYPE2 = 2;
const int32_t APP_DISTRIBUTION_TYPE3 = 3;
const int32_t INVALIDS_APP_DISTRIBUTION_TYPE1 = 0;
const int32_t INVALIDS_APP_DISTRIBUTION_TYPE2 = 7;

class AllowedAppDistributionTypesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};
void AllowedAppDistributionTypesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedAppDistributionTypesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
* @tc.name: TestOnSetPolicy001
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnSetPolicy function when policy is empty.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnSetPolicy001, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
* @tc.name: TestOnSetPolicy002
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnSetPolicy function when policy has value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnSetPolicy002, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(APP_DISTRIBUTION_TYPE2);
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret1 = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret1 == ERR_OK);
    ErrCode ret2 = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret2 == ERR_OK);
}

/**
* @tc.name: TestOnSetPolicy003
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnSetPolicy function when policy has invalid value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnSetPolicy003, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(INVALIDS_APP_DISTRIBUTION_TYPE2);
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
* @tc.name: TestOnSetPolicy004
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnSetPolicy function when policy has invalid value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnSetPolicy004, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(INVALIDS_APP_DISTRIBUTION_TYPE1);
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnSetPolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
* @tc.name: TestOnRemovePolicy001
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnRemovePolicy function when policy is empty.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnRemovePolicy001, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
* @tc.name: TestOnRemovePolicy002
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnRemovePolicy function when policy has value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnRemovePolicy002, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData1;
    policyData1.push_back(APP_DISTRIBUTION_TYPE1);
    policyData1.push_back(APP_DISTRIBUTION_TYPE2);
    std::vector<int32_t> currentData;
    currentData.push_back(APP_DISTRIBUTION_TYPE1);
    currentData.push_back(APP_DISTRIBUTION_TYPE2);
    currentData.push_back(APP_DISTRIBUTION_TYPE3);
    std::vector<int32_t> mergeData;
    ErrCode ret1 = plugin.OnRemovePolicy(policyData1, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret1 == ERR_OK);
    std::vector<int32_t> policyData2;
    policyData2.push_back(APP_DISTRIBUTION_TYPE1);
    policyData2.push_back(APP_DISTRIBUTION_TYPE2);
    policyData2.push_back(APP_DISTRIBUTION_TYPE3);
    ErrCode ret2 = plugin.OnRemovePolicy(policyData2, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret2 == ERR_OK);
}

/**
* @tc.name: TestOnRemovePolicy003
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnRemovePolicy function when policy has invalid value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnRemovePolicy003, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(INVALIDS_APP_DISTRIBUTION_TYPE2);
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
* @tc.name: TestOnRemovePolicy004
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnRemovePolicy function when policy has invalid value.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnRemovePolicy004, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(INVALIDS_APP_DISTRIBUTION_TYPE1);
    std::vector<int32_t> currentData;
    std::vector<int32_t> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(policyData, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
* @tc.name: TestOnAdminRemovePolicy001
* @tc.desc: Test AllowedAppDistributionTypesPlugin::OnAdminRemove function.
* @tc.type: FUNC
*/
HWTEST_F(AllowedAppDistributionTypesPluginTest, TestOnAdminRemovePolicy001, TestSize.Level1)
{
    AllowedAppDistributionTypesPlugin plugin;
    std::string adminName{"testAdminName"};
    std::vector<int32_t> policyData;
    policyData.push_back(APP_DISTRIBUTION_TYPE1);
    policyData.push_back(APP_DISTRIBUTION_TYPE2);
    std::vector<int32_t> mergeData1;
    mergeData1.push_back(APP_DISTRIBUTION_TYPE3);
    ErrCode ret1 = plugin.OnAdminRemove(adminName, policyData, mergeData1, DEFAULT_USER_ID);
    ASSERT_TRUE(ret1 == ERR_OK);
    std::vector<int32_t> mergeData2;
    ErrCode ret2 = plugin.OnAdminRemove(adminName, policyData, mergeData2, DEFAULT_USER_ID);
    ASSERT_TRUE(ret2 == ERR_OK);
}
}
}
}