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
#include "ipolicy_query.h"
#undef protected
#undef private

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "policy_query_factory.h"
#include "utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_PERMISSION_TAG_VERSION_23 = "version_23";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_APPLICATION = "ohos.permission.ENTERPRISE_MANAGE_APPLICATION";

class AllowedCollaborationServiceBundlesQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedCollaborationServiceBundlesQueryTest::SetUp() {}

void AllowedCollaborationServiceBundlesQueryTest::TearDown() {}

void AllowedCollaborationServiceBundlesQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedCollaborationServiceBundlesQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: GetPolicyName_ReturnCorrectValue_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::GetPolicyName function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, GetPolicyName_ReturnCorrectValue_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyName = queryObj->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES);
}

/**
 * @tc.name: GetPermission_ReturnCorrectPermission_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, GetPermission_ReturnCorrectPermission_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_23;
    std::string permission = queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag);
    EXPECT_EQ(permission, TEST_PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
}

/**
 * @tc.name: QueryPolicy_EmptyPolicyData_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::QueryPolicy function with empty policy data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, QueryPolicy_EmptyPolicyData_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: QueryPolicy_SingleItem_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::QueryPolicy function with single item.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, QueryPolicy_SingleItem_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData = "[\"com.test.app\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "com.test.app");
}

/**
 * @tc.name: QueryPolicy_MultipleItems_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::QueryPolicy function with multiple items.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, QueryPolicy_MultipleItems_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData = "[\"com.test.app1\", \"com.test.app2\", \"com.test.app3\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "com.test.app1");
    EXPECT_EQ(result[1], "com.test.app2");
    EXPECT_EQ(result[2], "com.test.app3");
}

/**
 * @tc.name: QueryPolicy_InvalidJsonFormat_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::QueryPolicy function with invalid JSON format.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, QueryPolicy_InvalidJsonFormat_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: QueryPolicy_DuplicateItems_Success
 * @tc.desc: Test AllowedCollaborationServiceBundlesQuery::QueryPolicy function with duplicate items.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedCollaborationServiceBundlesQueryTest, QueryPolicy_DuplicateItems_Success, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::ALLOWED_COLLABORATION_SERVICE_BUNDLES);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData = "[\"com.test.app\", \"com.test.app\"]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_EQ(ret, ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS