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
#include "external_manager_factory_mock.h"
#include "edm_os_account_manager_impl_mock.h"
#include "iext_info_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t INDEX_TWO = 2;

class QueryTrafficStatsPluginTest : public testing::Test {
protected:
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    std::shared_ptr<ExternalManagerFactoryMock> externalManagerFactoryMock_ = nullptr;
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountManagerMock_ = nullptr;
    void SetUp() override
    {
        Utils::SetEdmInitialEnv();
        bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
        QueryTrafficStatsPlugin::bundleMgr_ = bundleMgrMock_;
        
        externalManagerFactoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
        osAccountManagerMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
        QueryTrafficStatsPlugin::externalManagerFactory_ = externalManagerFactoryMock_;
        
        IExtInfoManager::appUidMap.clear();
    }

    void TearDown() override
    {
        bundleMgrMock_.reset();
        externalManagerFactoryMock_.reset();
        osAccountManagerMock_.reset();
        Utils::ResetTokenTypeAndUid();
        QueryTrafficStatsPlugin::bundleMgr_.reset();
        QueryTrafficStatsPlugin::externalManagerFactory_.reset();
        IExtInfoManager::appUidMap.clear();
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
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(-1)));
    AppExecFwk::BundleInfo bundleInfo;
    EXPECT_CALL(*bundleMgrMock_, GetBundleInfoV9)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_TWO>(bundleInfo), Return(false)));
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
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    int32_t replyCode;
    reply.ReadInt32(replyCode);
    ASSERT_EQ(replyCode, ERR_OK);
}

/**
 * @tc.name: OnGetPolicy_GetCurrentUserIdFailed_ReturnSystemAbnormally
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when GetCurrentUserId returns negative value.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_GetCurrentUserIdFailed_ReturnSystemAbnormally, TestSize.Level1)
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
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(-1));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: OnGetPolicy_CrossUserQuery_ReturnParameterVerificationFailed
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when querying other user's traffic.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_CrossUserQuery_ReturnParameterVerificationFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 101;
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);

    std::string policyData;
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnGetPolicy_SameUserQuery_Success
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when querying current user's traffic.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_SameUserQuery_Success, TestSize.Level1)
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
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);

    int32_t replyCode;
    reply.ReadInt32(replyCode);
    ASSERT_EQ(replyCode, ERR_OK);
}

/**
 * @tc.name: GetAppUid_FromAppUidMapSuccess_ReturnTrue
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when uid found in appUidMap with appIndex == 0.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_FromAppUidMapSuccess_ReturnTrue, TestSize.Level1)
{
    // 设置前置条件：在 appUidMap 中添加应用UID映射
    IExtInfoManager::appUidMap["com.test.app"] = 12345;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应从 appUidMap 中获取 uid
    ASSERT_TRUE(ret);
    ASSERT_EQ(uid, 12345);
}

/**
 * @tc.name: GetAppUid_FromAppUidMapButAppIndexNotZero_ReturnFalse
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when uid found in appUidMap but appIndex != 0.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_FromAppUidMapButAppIndexNotZero_ReturnFalse, TestSize.Level1)
{
    // 设置前置条件：在 appUidMap 中添加应用UID映射
    IExtInfoManager::appUidMap["com.test.app"] = 12345;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 1; // appIndex != 0
    networkInfo.accountId = 100;
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应返回 false
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetAppUid_NotInAppUidMap_GetFromBundleMgrSuccess
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when uid not in appUidMap, get from bundleMgr.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_NotInAppUidMap_GetFromBundleMgrSuccess, TestSize.Level1)
{
    // 设置前置条件：appUidMap 中没有该应用
    IExtInfoManager::appUidMap.clear();
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid)
        .WillOnce(DoAll(Return(12345)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应从 bundleMgr 获取 uid
    ASSERT_TRUE(ret);
    ASSERT_EQ(uid, 12345);
}

/**
 * @tc.name: GetAppUid_NotInAppUidMap_GetFromBundleMgrFailed_ReturnFalse
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when uid not in appUidMap and bundleMgr returns negative.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_NotInAppUidMap_GetFromBundleMgrFailed_ReturnFalse, TestSize.Level1)
{
    // 设置前置条件：appUidMap 中没有该应用
    IExtInfoManager::appUidMap.clear();
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(-1)));
    AppExecFwk::BundleInfo bundleInfo;
    EXPECT_CALL(*bundleMgrMock_, GetBundleInfoV9)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_TWO>(bundleInfo), Return(false)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应返回 false
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetAppUid_NotInAppUidMap_GetFromBundleInfoSuccess
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when GetApplicationUid returns negative but GetBundleInfoV9 success
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_NotInAppUidMap_GetFromBundleInfoSuccess, TestSize.Level1)
{
    // 设置前置条件：appUidMap 中没有该应用
    IExtInfoManager::appUidMap.clear();
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(-1)));
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.uid = 12345;
    EXPECT_CALL(*bundleMgrMock_, GetBundleInfoV9)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_TWO>(bundleInfo), Return(true)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应从 BundleInfo 获取 uid
    ASSERT_TRUE(ret);
    ASSERT_EQ(uid, 12345);
}

/**
 * @tc.name: GetAppUid_AppIndexNotZero_ReturnFalse
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when appIndex != 0 and not in appUidMap.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_AppIndexNotZero_ReturnFalse, TestSize.Level1)
{
    // 设置前置条件：appUidMap 中没有该应用
    IExtInfoManager::appUidMap.clear();
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 1; // appIndex != 0
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(-1)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应返回 false
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetAppUid_AppUidMapEmpty_GetFromBundleMgrSuccess
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when appUidMap is empty.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_AppUidMapEmpty_GetFromBundleMgrSuccess, TestSize.Level1)
{
    // 设置前置条件：appUidMap 为空
    IExtInfoManager::appUidMap.clear();
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(12345)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应从 bundleMgr 获取 uid
    ASSERT_TRUE(ret);
    ASSERT_EQ(uid, 12345);
}

/**
 * @tc.name: GetAppUid_BundleNameNotFoundInAppUidMap_GetFromBundleMgrSuccess
 * @tc.desc: Test QueryTrafficStatsPlugin::GetAppUid when bundleName not found in appUidMap.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, GetAppUid_BundleNameNotFoundInAppUidMap_GetFromBundleMgrSuccess, TestSize.Level1)
{
    // 设置前置条件：appUidMap 中有其他应用，但没有目标应用
    IExtInfoManager::appUidMap["com.other.app"] = 12346;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app"; // 不在 appUidMap 中
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    EXPECT_CALL(*bundleMgrMock_, GetApplicationUid).WillOnce(DoAll(Return(12345)));
    QueryTrafficStatsPlugin plugin;
    uint32_t uid = 0;
    bool ret = plugin.GetAppUid(networkInfo, uid);
    // 验证结果：应从 bundleMgr 获取 uid
    ASSERT_TRUE(ret);
    ASSERT_EQ(uid, 12345);
}

/**
 * @tc.name: OnGetPolicy_AppUidMapHasUid_Success
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when uid found in appUidMap.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_AppUidMapHasUid_Success, TestSize.Level1)
{
    // 设置前置条件：在 appUidMap 中添加应用UID映射
    IExtInfoManager::appUidMap["com.test.app"] = 12345;
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
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t replyCode;
    reply.ReadInt32(replyCode);
    ASSERT_EQ(replyCode, ERR_OK);
}

/**
 * @tc.name: OnGetPolicy_AppUidMapHasUidButAppIndexNotZero_ReturnFailed
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when uid found in appUidMap but appIndex != 0.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_AppUidMapHasUidButAppIndexNotZero_ReturnFailed, TestSize.Level1)
{
    // 设置前置条件：在 appUidMap 中添加应用UID映射
    IExtInfoManager::appUidMap["com.test.app"] = 12345;
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 1; // appIndex != 0
    networkInfo.accountId = 100;
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);
    std::string policyData;
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: OnGetPolicy_DifferentAccountId_ReturnParameterVerificationFailed
 * @tc.desc: Test QueryTrafficStatsPlugin::OnGetPolicy when accountId is different from currentUserId.
 * @tc.type: FUNC
 */
HWTEST_F(QueryTrafficStatsPluginTest, OnGetPolicy_DifferentAccountId_ReturnParameterVerificationFailed, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 200; // accountId != currentUserId
    networkInfo.type = 0;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.Marshalling(data);
    std::string policyData;
    EXPECT_CALL(*externalManagerFactoryMock_, CreateOsAccountManager)
        .WillOnce(Return(osAccountManagerMock_));
    EXPECT_CALL(*osAccountManagerMock_, GetCurrentUserId).WillOnce(Return(100));
    QueryTrafficStatsPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
