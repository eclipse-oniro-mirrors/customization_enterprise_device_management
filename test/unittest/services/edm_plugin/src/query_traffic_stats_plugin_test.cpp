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
#include <gmock/gmock.h>

#define protected public
#define private public
#include "query_traffic_stats_plugin.h"
#undef protected
#undef private
#include "edm_bundle_manager_impl_mock.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager_mock.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class QueryTrafficStatsPluginTest : public testing::Test {
protected:
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    void SetUp() override
    {
        Utils::SetEdmInitialEnv();
        bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
        QueryTrafficStatsPlugin::bundleMgr_ = bundleMgrMock_;
    }

    void TearDown() override
    {
        bundleMgrMock_.reset();
        Utils::ResetTokenTypeAndUid();
    }
};

/**
 * @tc.name: TestQueryTrafficStatsPluginConstructor
 * @tc.desc: Test QueryTrafficStatsPlugin::QueryTrafficStatsPlugin.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginConstructor, TestSize.Level1)
{
    QueryTrafficStatsPlugin plugin;
    ASSERT_EQ(plugin.policyCode_, EdmInterfaceCode::QUERY_TRAFFIC_STATS);
    ASSERT_EQ(plugin.policyName_, PolicyName::POLICY_QUERY_TRAFFIC_STATS);
    ASSERT_EQ(plugin.permissionConfig_.typePermissions.size(), 1);
    ASSERT_EQ(plugin.permissionConfig_.typePermissions[IPlugin::PermissionType::SUPER_DEVICE_ADMIN],
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    ASSERT_EQ(plugin.permissionConfig_.apiType, IPlugin::ApiType::PUBLIC);
    ASSERT_FALSE(plugin.needSave_);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicyInvalidUid
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy with invalid uid.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicyInvalidUid, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);

    std::string policyData;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(-1)));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicyInvalidNetworkType
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy with invalid network type.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicyInvalidNetworkType, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 2;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);

    std::string policyData;
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicyInvalidTimeRange
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy with invalid time range.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicyInvalidTimeRange, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = 2000;
    networkInfo.endTime = 1000;
    networkInfo.Marshalling(data);

    std::string policyData;
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicyNegativeStartTime
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy with negative start time.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicyNegativeStartTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = -1;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);

    std::string policyData;
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicyNegativeEndTime
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy with negative end time.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicyNegativeEndTime, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = -1;
    networkInfo.Marshalling(data);

    std::string policyData;
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryTrafficStatsPluginOnGetPolicySuccess
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy success.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, TestQueryTrafficStatsPluginOnGetPolicySuccess, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.simId = 12345;
    networkInfo.Marshalling(data);

    std::string policyData;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(1)));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    int32_t replyCode;
    reply.ReadInt32(replyCode);
    ASSERT_EQ(replyCode, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
