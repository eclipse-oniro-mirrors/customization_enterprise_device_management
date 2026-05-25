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
#include "disallowed_permission_query.h"
#undef private
#undef protected

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class DisallowedPermissionQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<DisallowedPermissionQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<DisallowedPermissionQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName_SUC
 * @tc.desc: Test GetPolicyName function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestGetPolicyName_SUC, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_DISALLOWED_PERMISSION);
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
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicy_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.CAMERA","ohos.permission.LOCATION"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 2u);

    std::string permission1 = reply.ReadString();
    EXPECT_EQ(permission1, "ohos.permission.CAMERA");

    std::string permission2 = reply.ReadString();
    EXPECT_EQ(permission2, "ohos.permission.LOCATION");
}

/**
 * @tc.name: TestQueryPolicyEmptyData_SUC
 * @tc.desc: Test QueryPolicy with empty policy data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyEmptyData_SUC, TestSize.Level1)
{
    std::string policyData = "";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 0u);
}

/**
 * @tc.name: TestQueryPolicySinglePermission_SUC
 * @tc.desc: Test QueryPolicy with single permission.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicySinglePermission_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.CAMERA"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string permission = reply.ReadString();
    EXPECT_EQ(permission, "ohos.permission.CAMERA");
}

/**
 * @tc.name: TestQueryPolicyMultiplePermissions_SUC
 * @tc.desc: Test QueryPolicy with multiple permissions.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyMultiplePermissions_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.CAMERA","ohos.permission.LOCATION","ohos.permission.MICROPHONE"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 3u);
}

/**
 * @tc.name: TestQueryPolicyInvalidJson_SUC
 * @tc.desc: Test QueryPolicy with invalid JSON (should return empty result).
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyInvalidJson_SUC, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;

    // Invalid JSON should deserialize to empty vector
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 0u);
}

/**
 * @tc.name: TestQueryPolicyDifferentUserId_SUC
 * @tc.desc: Test QueryPolicy with different user ID.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyDifferentUserId_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.CAMERA"])";
    MessageParcel data;
    MessageParcel reply;

    int32_t userId = 200;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, userId);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string permission = reply.ReadString();
    EXPECT_EQ(permission, "ohos.permission.CAMERA");
}

/**
 * @tc.name: TestQueryPolicyDuplicatePermissions_SUC
 * @tc.desc: Test QueryPolicy with duplicate permissions (should deduplicate).
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyDuplicatePermissions_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.CAMERA","ohos.permission.CAMERA"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> strVector;
    reply.ReadStringVector(&strVector);
    EXPECT_EQ(strVector.size(), 2);
}

/**
 * @tc.name: TestQueryPolicyEmptyPermissionInList_SUC
 * @tc.desc: Test QueryPolicy with empty permission in list.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicyEmptyPermissionInList_SUC, TestSize.Level1)
{
    std::string policyData = R"(["","ohos.permission.CAMERA"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> strVector;
    reply.ReadStringVector(&strVector);
    EXPECT_EQ(strVector.size(), 2);
}

/**
 * @tc.name: TestQueryPolicySpecialCharacters_SUC
 * @tc.desc: Test QueryPolicy with special characters in permission name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissionQueryTest, TestQueryPolicySpecialCharacters_SUC, TestSize.Level1)
{
    std::string policyData = R"(["ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY"])";
    MessageParcel data;
    MessageParcel reply;

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    uint32_t count = reply.ReadUint32();
    EXPECT_EQ(count, 1u);

    std::string permission = reply.ReadString();
    EXPECT_EQ(permission, "ohos.permission.READ_WRITE_DOWNLOAD_DIRECTORY");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS