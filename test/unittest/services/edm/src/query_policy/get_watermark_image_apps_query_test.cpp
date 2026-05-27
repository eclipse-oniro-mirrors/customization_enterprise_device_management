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
#include "get_watermark_image_apps_query.h"
#undef private
#undef protected

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "watermark_image_serializer.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class GetWatermarkImageAppsQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<GetWatermarkImageAppsQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<GetWatermarkImageAppsQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName_SUC
 * @tc.desc: Test GetPolicyName function returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestGetPolicyName_SUC, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_WATERMARK_IMAGE_POLICY);
}

/**
 * @tc.name: TestGetPermission_SUC
 * @tc.desc: Test GetPermission function returns correct permission.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestGetPermission_SUC, TestSize.Level1)
{
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    std::string permission2 = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "test_tag");
    EXPECT_EQ(permission2, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
}

/**
 * @tc.name: TestQueryPolicy_SUC
 * @tc.desc: Test QueryPolicy with valid data containing multiple apps matching accountId.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicy_SUC, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080},
        {"bundleName":"com.test.app2", "accountId":100, "fileName":"edm_456", "width":800, "height":600}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 2u);
    EXPECT_EQ(bundleNames[0], "com.test.app1");
    EXPECT_EQ(bundleNames[1], "com.test.app2");
}

/**
 * @tc.name: TestQueryPolicySingleApp_SUC
 * @tc.desc: Test QueryPolicy with only one app matching accountId.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicySingleApp_SUC, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 1u);
    EXPECT_EQ(bundleNames[0], "com.test.app1");
}

/**
 * @tc.name: TestQueryPolicyNoMatch_SUC
 * @tc.desc: Test QueryPolicy when accountId does not match any app, returns empty list.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyNoMatch_SUC, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(200); // accountId that doesn't match

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 0u);
}

/**
 * @tc.name: TestQueryPolicyDeserializeFailed_FAIL
 * @tc.desc: Test QueryPolicy with invalid JSON that causes Deserialize to fail.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyDeserializeFailed_FAIL, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyEmptyPolicyData_SUC
 * @tc.desc: Test QueryPolicy with empty policy data, Deserialize succeeds with empty map, returns empty bundleNames.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyEmptyPolicyData_SUC, TestSize.Level1)
{
    std::string policyData = "";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 0u);
}

/**
 * @tc.name: TestQueryPolicyAccountIdZero_FAIL
 * @tc.desc: Test QueryPolicy with accountId equal to 0, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyAccountIdZero_FAIL, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(0); // accountId = 0

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyAccountIdNegative_FAIL
 * @tc.desc: Test QueryPolicy with negative accountId, should return PARAMETER_VERIFICATION_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyAccountIdNegative_FAIL, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(-1); // accountId = -1

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyMultipleAccounts_SUC
 * @tc.desc: Test QueryPolicy with data containing multiple different accountIds
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyMultipleAccounts_SUC, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080},
        {"bundleName":"com.test.app2", "accountId":200, "fileName":"edm_456", "width":800, "height":600},
        {"bundleName":"com.test.app3", "accountId":100, "fileName":"edm_789", "width":640, "height":480}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // query for accountId 100

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 2u);
    EXPECT_EQ(bundleNames[0], "com.test.app1");
    EXPECT_EQ(bundleNames[1], "com.test.app3");
}

/**
 * @tc.name: TestQueryPolicyInvalidJsonMissingFields_FAIL
 * @tc.desc: Test QueryPolicy with JSON missing required fields, Deserialize should fail.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyInvalidJsonMissingFields_FAIL, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1"}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestQueryPolicyWithIntervalsRowCol_SUC
 * @tc.desc: Test QueryPolicy with watermark data containing intervalsRow and intervalsCol fields.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyWithIntervalsRowCol_SUC, TestSize.Level1)
{
    std::string policyData = R"([
        {"bundleName":"com.test.app1", "accountId":100, "fileName":"edm_123", "width":1920, "height":1080,
        "intervalsRow":10, "intervalsCol":20}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(100); // accountId

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<std::string> bundleNames;
    reply.ReadStringVector(&bundleNames);
    EXPECT_EQ(bundleNames.size(), 1u);
    EXPECT_EQ(bundleNames[0], "com.test.app1");
}

/**
 * @tc.name: TestQueryPolicyDeserializeFailedAndAccountIdInvalid_FAIL
 * @tc.desc: Test QueryPolicy where Deserialize fails first, accountId check should not be reached.
 * @tc.type: FUNC
 */
HWTEST_F(GetWatermarkImageAppsQueryTest, TestQueryPolicyDeserializeFailedAndAccountIdInvalid_FAIL, TestSize.Level1)
{
    std::string policyData = "not_json_at_all";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(-1); // invalid accountId, but Deserialize fails first

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS