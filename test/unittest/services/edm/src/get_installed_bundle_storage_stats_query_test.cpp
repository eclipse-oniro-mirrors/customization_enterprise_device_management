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

#include <gtest/gtest.h>

#define private public
#define protected public
#include "get_installed_bundle_storage_stats_query.h"
#undef protected
#undef private

#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_BUNDLE_SIZE = 3;
const int32_t TEST_APP_SIZE = 1024;
const int32_t TEST_DATA_SIZE = 2048;
class GetInstalledBundleStorageStatsQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;
};

void GetInstalledBundleStorageStatsQueryTest::SetUp() {
}

void GetInstalledBundleStorageStatsQueryTest::TearDown() {
}

/**
 * @tc.name: GetInstalledBundleStorageStatsQueryBasicInfo
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery basic info check
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, GetInstalledBundleStorageStatsQueryBasicInfo, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
        std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::string permissionTag;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_BUNDLE_STORAGE_STATS);
}

/**
 * @tc.name: TestQueryPolicyWithEmptyBundles
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::QueryPolicy with empty bundles
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestQueryPolicyWithEmptyBundles, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::string policyValue{"GetInstalledBundleStorageStatsQuery"};
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyWithExceedMaxBundles
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::QueryPolicy with exceed max bundles
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestQueryPolicyWithExceedMaxBundles, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::string policyValue{"GetInstalledBundleStorageStatsQuery"};
    MessageParcel data;
    data.WriteUint32(EdmConstants::POLICIES_MAX_SIZE + 1);
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyWithInvalidData
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::QueryPolicy with invalid data
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestQueryPolicyWithInvalidData, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj = std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::string policyValue{"GetInstalledBundleStorageStatsQuery"};
    MessageParcel data;
    data.WriteUint32(1);
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestAddResultToReplySuccess
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::AddResultToReply success
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestAddResultToReplySuccess, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
        std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    OHOS::AppExecFwk::BundleStorageStats stat;
    stat.bundleName = "com.test.app";
    stat.bundleStats = {TEST_APP_SIZE, TEST_DATA_SIZE, 0, 0, 0};
    bundleStats.push_back(stat);
    MessageParcel reply;
    ErrCode ret = queryObj->AddResultToReply(bundleStats, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddResultToReplyWithInvalidSize
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::AddResultToReply with invalid size
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestAddResultToReplyWithInvalidSize, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
        std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    OHOS::AppExecFwk::BundleStorageStats stat;
    stat.bundleName = "com.test.app";
    stat.bundleStats = {TEST_APP_SIZE};
    bundleStats.push_back(stat);
    MessageParcel reply;
    ErrCode ret = queryObj->AddResultToReply(bundleStats, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddResultToReplyWithEmptyVector
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::AddResultToReply with empty vector
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestAddResultToReplyWithEmptyVector, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
        std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    MessageParcel reply;
    ErrCode ret = queryObj->AddResultToReply(bundleStats, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddResultToReplyWithMultipleBundles
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::AddResultToReply with multiple bundles
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestAddResultToReplyWithMultipleBundles, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
       std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    for (int32_t i = 1; i <= TEST_BUNDLE_SIZE; i++) {
        OHOS::AppExecFwk::BundleStorageStats stat;
        stat.bundleName = "com.test.app" + std::to_string(i);
        stat.bundleStats = {TEST_APP_SIZE * i, TEST_DATA_SIZE * i, 0, 0, 0};
        bundleStats.push_back(stat);
    }
    MessageParcel reply;
    ErrCode ret = queryObj->AddResultToReply(bundleStats, reply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddResultToReplyWithOvermaxBundles
 * @tc.desc: Test GetInstalledBundleStorageStatsQuery::AddResultToReply with over max bundles
 * @tc.type: FUNC
 */
HWTEST_F(GetInstalledBundleStorageStatsQueryTest, TestAddResultToReplyWithOvermaxBundles, TestSize.Level1)
{
    std::shared_ptr<GetInstalledBundleStorageStatsQuery> queryObj =
       std::make_shared<GetInstalledBundleStorageStatsQuery>();
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    for (int32_t i = 1; i <= static_cast<int32_t>(EdmConstants::POLICIES_MAX_SIZE) + 1; i++) {
        OHOS::AppExecFwk::BundleStorageStats stat;
        stat.bundleName = "com.test.app" + std::to_string(i);
        stat.bundleStats = {TEST_APP_SIZE * i, TEST_DATA_SIZE * i, 0, 0, 0};
        bundleStats.push_back(stat);
    }
    MessageParcel reply;
    ErrCode ret = queryObj->AddResultToReply(bundleStats, reply);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
