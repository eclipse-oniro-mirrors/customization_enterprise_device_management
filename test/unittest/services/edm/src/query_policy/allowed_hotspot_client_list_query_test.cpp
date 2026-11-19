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
#include "allowed_hotspot_client_list_query.h"
#undef private
#undef protected

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class AllowedHotspotClientListQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<AllowedHotspotClientListQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<AllowedHotspotClientListQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName
 * @tc.desc: Test GetPolicyName returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestGetPolicyName, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ALLOWED_HOTSPOT_CLIENT_LIST);
}

/**
 * @tc.name: TestGetPermission
 * @tc.desc: Test GetPermission returns correct permission for different admin types.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestGetPermission, TestSize.Level1)
{
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI);
    std::string permission2 = query_->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "test_tag");
    EXPECT_EQ(permission2, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI);
}

/**
 * @tc.name: TestQueryPolicySuc
 * @tc.desc: Test QueryPolicy with valid JSON containing MAC addresses.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestQueryPolicySuc, TestSize.Level1)
{
    std::string policyData = R"(["00:11:22:33:44:55","AA:BB:CC:DD:EE:FF"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> macAddresses;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, macAddresses));
    EXPECT_EQ(macAddresses.size(), 2u);
}

/**
 * @tc.name: TestQueryPolicyEmpty
 * @tc.desc: Test QueryPolicy with empty policy data returns empty list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestQueryPolicyEmpty, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> macAddresses;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, macAddresses));
    EXPECT_TRUE(macAddresses.empty());
}

/**
 * @tc.name: TestQueryPolicyInvalidJson
 * @tc.desc: Test QueryPolicy with invalid JSON causes Deserialize failure.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestQueryPolicyInvalidJson, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestQueryPolicyNotArray
 * @tc.desc: Test QueryPolicy with JSON that is not an array.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestQueryPolicyNotArray, TestSize.Level1)
{
    std::string policyData = R"({"mac":"00:11:22:33:44:55"})";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestQueryPolicySingleMac
 * @tc.desc: Test QueryPolicy with a single MAC address in JSON array.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedHotspotClientListQueryTest, TestQueryPolicySingleMac, TestSize.Level1)
{
    std::string policyData = R"(["00:11:22:33:44:55"])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> macAddresses;
    ASSERT_TRUE(ArrayStringSerializer::GetInstance()->GetPolicy(reply, macAddresses));
    EXPECT_EQ(macAddresses.size(), 1u);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
