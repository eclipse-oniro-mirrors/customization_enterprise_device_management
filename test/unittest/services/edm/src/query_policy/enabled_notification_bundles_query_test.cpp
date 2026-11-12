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

#include <string>
#include <vector>

#define private public
#define protected public
#include "enabled_notification_bundles_query.h"
#undef protected
#undef private

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "message_parcel.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t ACCOUNT_ID = 100;
const std::string NO_PERMISSION_TAG = "";
} // namespace

class EnabledNotificationBundlesQueryMock : public EnabledNotificationBundlesQuery {
public:
    std::vector<int32_t> readUserIds_;
    std::vector<std::string> bundleList_;
    ErrCode readRet_ = ERR_OK;

    ErrCode ReadEnabledBundles(int32_t userId, std::vector<std::string> &bundleList) override
    {
        readUserIds_.push_back(userId);
        bundleList = bundleList_;
        return readRet_;
    }
};

class EnabledNotificationBundlesQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<EnabledNotificationBundlesQueryMock>();
    }

    std::shared_ptr<EnabledNotificationBundlesQueryMock> query_ = nullptr;
};

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.GetPolicyName_001
 * @tc.desc: GetPolicyName returns the policy name of the enabled notification bundles policy.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, GetPolicyName_001, TestSize.Level1)
{
    EXPECT_EQ(query_->GetPolicyName(), PolicyName::POLICY_ENABLED_NOTIFICATION_BUNDLES);
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.GetPermission_001
 * @tc.desc: GetPermission returns the same non-empty permission for every administrator type.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, GetPermission_001, TestSize.Level1)
{
    std::string superPermission =
        query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, NO_PERMISSION_TAG);
    std::string byodPermission =
        query_->GetPermission(IPlugin::PermissionType::BYOD_DEVICE_ADMIN, NO_PERMISSION_TAG);
    std::string normalPermission =
        query_->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, NO_PERMISSION_TAG);
    EXPECT_EQ(superPermission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION);
    EXPECT_EQ(byodPermission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION);
    EXPECT_EQ(normalPermission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NOTIFICATION);
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_001
 * @tc.desc: The self view reads the policy data and does not call the notification service.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_001, TestSize.Level1)
{
    std::string policyData = R"(["com.example.a","com.example.b"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, ACCOUNT_ID, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> bundleNames;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, bundleNames));
    EXPECT_EQ(bundleNames.size(), 2U);
    EXPECT_TRUE(query_->readUserIds_.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_002
 * @tc.desc: The four argument overload falls back to the self view.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_002, TestSize.Level1)
{
    std::string policyData = R"(["com.example.a"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, ACCOUNT_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> bundleNames;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, bundleNames));
    EXPECT_EQ(bundleNames.size(), 1U);
    EXPECT_TRUE(query_->readUserIds_.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_003
 * @tc.desc: The all view returns the list read from the notification service.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_003, TestSize.Level1)
{
    query_->bundleList_ = {"com.example.a", "com.example.c"};
    std::string policyData = R"(["com.example.a"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, ACCOUNT_ID, true);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(query_->readUserIds_.size(), 1U);
    EXPECT_EQ(query_->readUserIds_[0], ACCOUNT_ID);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> bundleNames;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, bundleNames));
    EXPECT_EQ(bundleNames.size(), 2U);
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_004
 * @tc.desc: The all view reports a timeout when the notification service read fails.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_004, TestSize.Level1)
{
    query_->readRet_ = EdmReturnErrCode::EXECUTE_TIME_OUT;
    std::string policyData = R"(["com.example.a"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, ACCOUNT_ID, true);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_EQ(query_->readUserIds_.size(), 1U);
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_005
 * @tc.desc: The self view still succeeds when the notification service read fails.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_005, TestSize.Level1)
{
    query_->readRet_ = EdmReturnErrCode::EXECUTE_TIME_OUT;
    std::string policyData = R"(["com.example.a"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, ACCOUNT_ID, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(query_->readUserIds_.empty());
}

/**
 * @tc.name: EnabledNotificationBundlesQueryTest.QueryPolicy_006
 * @tc.desc: Both views reject an account id that is zero or negative.
 * @tc.type: FUNC
 */
HWTEST_F(EnabledNotificationBundlesQueryTest, QueryPolicy_006, TestSize.Level1)
{
    std::string policyData = R"(["com.example.a"])";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(query_->QueryPolicy(policyData, data, reply, 0, false), EdmReturnErrCode::UID_INVALID);
    EXPECT_EQ(query_->QueryPolicy(policyData, data, reply, 0, true), EdmReturnErrCode::UID_INVALID);
    EXPECT_EQ(query_->QueryPolicy(policyData, data, reply, -1, true), EdmReturnErrCode::UID_INVALID);
    EXPECT_TRUE(query_->readUserIds_.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
