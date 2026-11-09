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

#define private public
#define protected public
#include "optimization_battery_exclusion_apps_plugin.h"
#undef protected
#undef private

#include "optimization_battery_exclusion_apps_plugin_test.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_bundle_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
void OptimizationBatteryExclusionAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void OptimizationBatteryExclusionAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSetEmptyData
 * @tc.desc: Test OnBasicSetPolicy with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestSetEmptyData, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestSetValidData
 * @tc.desc: Test OnBasicSetPolicy with valid bundle names.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestSetValidData, TestSize.Level1)
{
    auto bundleMgrMock = std::make_shared<EdmBundleManagerImplMock>();
    auto factoryMock = std::make_shared<ExternalManagerFactoryMock>();
    EXPECT_CALL(*factoryMock, CreateBundleManager).WillRepeatedly(Return(bundleMgrMock));
    EXPECT_CALL(*bundleMgrMock, GetBundleNameByAppId)
        .WillRepeatedly(DoAll(SetArgReferee<1>("com.example.app"), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock, IsBundleInstalled).WillRepeatedly(Return(true));

    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    plugin.externalManagerFactory_ = factoryMock;
    std::vector<std::string> data = {"com.example.app1", "com.example.app2"};
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestSetExceedMaxSize
 * @tc.desc: Test OnBasicSetPolicy when data exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestSetExceedMaxSize, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    plugin.overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    std::vector<std::string> data(EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE + 1);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = "com.example.app" + std::to_string(i);
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestSetMergePolicy
 * @tc.desc: Test OnBasicSetPolicy with existing data merges correctly.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestSetMergePolicy, TestSize.Level1)
{
    auto bundleMgrMock = std::make_shared<EdmBundleManagerImplMock>();
    auto factoryMock = std::make_shared<ExternalManagerFactoryMock>();
    EXPECT_CALL(*factoryMock, CreateBundleManager).WillRepeatedly(Return(bundleMgrMock));
    EXPECT_CALL(*bundleMgrMock, GetBundleNameByAppId)
        .WillRepeatedly(DoAll(SetArgReferee<1>("com.example.app"), Return(ERR_OK)));
    EXPECT_CALL(*bundleMgrMock, IsBundleInstalled).WillRepeatedly(Return(true));

    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    plugin.externalManagerFactory_ = factoryMock;
    std::vector<std::string> data = {"com.example.app3"};
    std::vector<std::string> currentData = {"com.example.app1", "com.example.app2"};
    std::vector<std::string> mergeData = {"com.example.app1", "com.example.app2"};
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 3);
    ASSERT_EQ(mergeData.size(), 3);
}

/**
 * @tc.name: TestSetCurrentDataFull
 * @tc.desc: Test OnBasicSetPolicy when currentData is already at max size.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestSetCurrentDataFull, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    plugin.overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    std::vector<std::string> currentData;
    for (int32_t i = 0; i < EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE; ++i) {
        currentData.push_back("com.example.app" + std::to_string(i));
    }
    std::vector<std::string> mergeData = currentData;
    std::vector<std::string> data = {"com.example.newapp"};
    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}

/**
 * @tc.name: TestRemoveEmptyData
 * @tc.desc: Test OnBasicRemovePolicy with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestRemoveEmptyData, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestRemoveExistingData
 * @tc.desc: Test OnBasicRemovePolicy removes matching entries.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestRemoveExistingData, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    std::vector<std::string> data = {"com.example.app1"};
    std::vector<std::string> currentData = {"com.example.app1", "com.example.app2"};
    std::vector<std::string> mergeData = {"com.example.app1", "com.example.app2"};
    ErrCode ret = plugin.OnBasicRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData.size(), 1);
    ASSERT_EQ(currentData[0], "com.example.app2");
}

/**
 * @tc.name: TestRemoveNonExistentData
 * @tc.desc: Test OnBasicRemovePolicy with data not in currentData.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestRemoveNonExistentData, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    std::vector<std::string> data = {"com.example.notexist"};
    std::vector<std::string> currentData = {"com.example.app1", "com.example.app2"};
    std::vector<std::string> mergeData = {"com.example.app1", "com.example.app2"};
    std::vector<std::string> originalCurrentData = currentData;
    ErrCode ret = plugin.OnBasicRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(currentData, originalCurrentData);
}

/**
 * @tc.name: TestRemoveExceedMaxSize
 * @tc.desc: Test OnBasicRemovePolicy when data exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(OptimizationBatteryExclusionAppsPluginTest, TestRemoveExceedMaxSize, TestSize.Level1)
{
    OptimizationBatteryExclusionAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE;
    plugin.overMaxReturnErrCode_ = EdmReturnErrCode::POLICY_LIST_OVER_SIZE;
    std::vector<std::string> data(EdmConstants::OPTIMIZATION_BATTERY_EXCLUSION_APPS_MAX_SIZE + 1);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = "com.example.app" + std::to_string(i);
    }
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    ErrCode ret = plugin.OnBasicRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::POLICY_LIST_OVER_SIZE);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
