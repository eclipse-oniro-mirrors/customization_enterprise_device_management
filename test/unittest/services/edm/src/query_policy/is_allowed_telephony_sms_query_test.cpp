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

#include "is_allowed_telephony_sms_query.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::string SMS_TYPE_INCOMING = "incoming";
const std::string NUMBER_IN_LIST = "11111111";
const std::string NUMBER_NOT_IN_LIST = "99999999";

class IsAllowedTelephonySmsQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<IsAllowedTelephonySmsQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<IsAllowedTelephonySmsQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName
 * @tc.desc: Test IsAllowedTelephonySmsQuery::GetPolicyName returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestGetPolicyName, TestSize.Level1)
{
    EXPECT_EQ(query_->GetPolicyName(), PolicyName::POLICY_TELEPHONY_SMS_POLICY);
}

/**
 * @tc.name: TestGetPermission
 * @tc.desc: Test IsAllowedTelephonySmsQuery::GetPermission returns correct permission.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestGetPermission, TestSize.Level1)
{
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    std::string permission2 = query_->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "test_tag");
    EXPECT_EQ(permission2, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
}

/**
 * @tc.name: TestQueryPolicyTrustListMatch
 * @tc.desc: Test QueryPolicy when number is in the whitelist (TRUST_LIST), should allow.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyTrustListMatch, TestSize.Level1)
{
    std::string policyData = R"({"incoming":{"policyFlag":1,"numberList":["11111111","22222222"]}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestQueryPolicyTrustListNoMatch
 * @tc.desc: Test QueryPolicy when number is not in the whitelist (TRUST_LIST), should not allow.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyTrustListNoMatch, TestSize.Level1)
{
    std::string policyData = R"({"incoming":{"policyFlag":1,"numberList":["11111111","22222222"]}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_NOT_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestQueryPolicyBlockListMatch
 * @tc.desc: Test QueryPolicy when number is in the block list, should not allow.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyBlockListMatch, TestSize.Level1)
{
    std::string policyData = R"({"incoming":{"policyFlag":0,"numberList":["11111111","22222222"]}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: TestQueryPolicyBlockListNoMatch
 * @tc.desc: Test QueryPolicy when number is not in the block list, should allow.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyBlockListNoMatch, TestSize.Level1)
{
    std::string policyData = R"({"incoming":{"policyFlag":0,"numberList":["11111111","22222222"]}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_NOT_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestQueryPolicySmsTypeNotExist
 * @tc.desc: Test QueryPolicy when smsType does not exist, should allow by default.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicySmsTypeNotExist, TestSize.Level1)
{
    std::string policyData = R"({"outgoing":{"policyFlag":1,"numberList":["11111111"]}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: TestQueryPolicyInvalidJson
 * @tc.desc: Test QueryPolicy with invalid JSON causes Deserialize failure.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyInvalidJson, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestQueryPolicyInvalidField
 * @tc.desc: Test QueryPolicy with policy data missing numberList/policyFlag causes Deserialize failure.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedTelephonySmsQueryTest, TestQueryPolicyInvalidField, TestSize.Level1)
{
    std::string policyData = R"({"incoming":{"numberList":"11111111"}})";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(SMS_TYPE_INCOMING);
    data.WriteString(NUMBER_IN_LIST);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
