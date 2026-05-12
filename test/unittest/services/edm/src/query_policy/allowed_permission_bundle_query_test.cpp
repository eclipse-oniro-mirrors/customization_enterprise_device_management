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

#define private public
#define protected public
#include "allowed_permission_bundle_query.h"
#undef private
#undef protected

#include "allowed_permission_bundle_serializer.h"
#include "application_instance.h"
#include "edm_constants.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class AllowedPermissionBundleQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<AllowedPermissionBundleQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<AllowedPermissionBundleQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName_SUC
 * @tc.desc: Test GetPolicyName function.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestGetPolicyName_SUC, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ALLOWED_PERMISSION_BUNDLE);
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    std::string permission2 = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "test_tag");
    EXPECT_EQ(permission2, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

/**
 * @tc.name: TestQueryPolicy_SUC
 * @tc.desc: Test QueryPolicy function with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicy_SUC, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0},{"appIdentifier":"com.test.app2","accountId":100,"appIndex":0}]})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 2u);

    std::string appIdentifier1 = reply.ReadString();
    EXPECT_EQ(appIdentifier1, "com.test.app1");

    int32_t accountId1 = reply.ReadInt32();
    EXPECT_EQ(accountId1, EdmConstants::DEFAULT_USER_ID);

    int32_t appIndex1 = reply.ReadInt32();
    EXPECT_EQ(appIndex1, 0);

    std::string appIdentifier2 = reply.ReadString();
    EXPECT_EQ(appIdentifier2, "com.test.app2");

    int32_t accountId2 = reply.ReadInt32();
    EXPECT_EQ(accountId2, EdmConstants::DEFAULT_USER_ID);

    int32_t appIndex2 = reply.ReadInt32();
    EXPECT_EQ(appIndex2, 0);
}

/**
 * @tc.name: TestQueryPolicyEmptyPermission_FAIL
 * @tc.desc: Test QueryPolicy with empty permission name.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyEmptyPermission_FAIL, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}]})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(""); // Empty permission

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyPermissionNotExist_SUC
 * @tc.desc: Test QueryPolicy when permission not in policy data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyPermissionNotExist_SUC, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.LOCATION":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}]})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA"); // Permission not in policy

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 0u); // Should return empty list
}

/**
 * @tc.name: TestQueryPolicyEmptyPolicyData_SUC
 * @tc.desc: Test QueryPolicy with empty policy data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyEmptyPolicyData_SUC, TestSize.Level1)
{
    std::string policyData = "";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 0u);
}

/**
 * @tc.name: TestQueryPolicyMultipleApps_SUC
 * @tc.desc: Test QueryPolicy with multiple apps for same permission.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyMultipleApps_SUC, TestSize.Level1)
{
    std::string policyData = R"({
        "ohos.permission.CAMERA":[
            {"appIdentifier":"com.test.app1","accountId":100,"appIndex":0},
            {"appIdentifier":"com.test.app2","accountId":100,"appIndex":0},
            {"appIdentifier":"com.test.app3","accountId":100,"appIndex":0}
        ]
    })";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 3u);
}

/**
 * @tc.name: TestQueryPolicyMultiplePermissions_SUC
 * @tc.desc: Test QueryPolicy with multiple permissions in policy data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyMultiplePermissions_SUC, TestSize.Level1)
{
    std::string policyData = R"({
        "ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}],
        "ohos.permission.LOCATION":[{"appIdentifier":"com.test.app2","accountId":100,"appIndex":0}]
    })";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.LOCATION");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string appIdentifier = reply.ReadString();
    EXPECT_EQ(appIdentifier, "com.test.app2");
}

/**
 * @tc.name: TestQueryPolicyInvalidJson_SUC
 * @tc.desc: Test QueryPolicy with invalid JSON (should still work with empty result).
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyInvalidJson_SUC, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    // Invalid JSON should deserialize to empty map
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 0u);
}

/**
 * @tc.name: TestQueryPolicyReadPermissionFail_FAIL
 * @tc.desc: Test QueryPolicy when reading permission name fails.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyReadPermissionFail_FAIL, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}]})";
    MessageParcel data;
    MessageParcel reply;
    // Not writing permission name

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyDifferentUserId_SUC
 * @tc.desc: Test QueryPolicy with different user ID.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyDifferentUserId_SUC, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":0}]})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    int32_t userId = 200;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, userId);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string appIdentifier = reply.ReadString();
    EXPECT_EQ(appIdentifier, "com.test.app1");

    int32_t accountId = reply.ReadInt32();
    EXPECT_EQ(accountId, userId); // Should use the userId parameter

    int32_t appIndex = reply.ReadInt32();
    EXPECT_EQ(appIndex, 0);
}

/**
 * @tc.name: TestQueryPolicyWithAppIndex_SUC
 * @tc.desc: Test QueryPolicy with different app index.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedPermissionBundleQueryTest, TestQueryPolicyWithAppIndex_SUC, TestSize.Level1)
{
    std::string policyData = R"({"ohos.permission.CAMERA":[{"appIdentifier":"com.test.app1","accountId":100,"appIndex":1}]})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("ohos.permission.CAMERA");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string appIdentifier = reply.ReadString();
    EXPECT_EQ(appIdentifier, "com.test.app1");

    int32_t accountId = reply.ReadInt32();
    EXPECT_EQ(accountId, EdmConstants::DEFAULT_USER_ID);

    int32_t appIndex = reply.ReadInt32();
    EXPECT_EQ(appIndex, 1); // Should match the app index in policy
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS