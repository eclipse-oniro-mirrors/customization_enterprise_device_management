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
#include <message_parcel.h>

#include "array_string_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "is_app_kiosk_allowed_query.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
std::string BuildKioskPolicy(const std::vector<std::string> &apps)
{
    std::string policyData;
    ArrayStringSerializer::GetInstance()->Serialize(apps, policyData);
    return policyData;
}
}

class IsAppKioskAllowedQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void IsAppKioskAllowedQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void IsAppKioskAllowedQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_ReturnCorrectValue_Success
 * @tc.desc: Test IsAppKioskAllowedQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(IsAppKioskAllowedQueryTest, GetPolicyName_ReturnCorrectValue_Success, TestSize.Level1)
{
    IsAppKioskAllowedQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_ALLOWED_KIOSK_APPS);
}

/**
 * @tc.name: GetPermission_ReturnEmpty_Success
 * @tc.desc: Test IsAppKioskAllowedQuery needs no permission of its own.
 * @tc.type: FUNC
 */
HWTEST_F(IsAppKioskAllowedQueryTest, GetPermission_ReturnEmpty_Success, TestSize.Level1)
{
    IsAppKioskAllowedQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        std::string(""));
}

/**
 * @tc.name: QueryPolicy_AppAllowed_ReturnsTrue
 * @tc.desc: Test IsAppKioskAllowedQuery::QueryPolicy reports the app inside the kiosk whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(IsAppKioskAllowedQueryTest, QueryPolicy_AppAllowed_ReturnsTrue, TestSize.Level1)
{
    IsAppKioskAllowedQuery query;
    std::string policyData = BuildKioskPolicy({ "com.test.a", "com.test.b" });
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.test.b");
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/**
 * @tc.name: QueryPolicy_AppNotAllowed_ReturnsFalse
 * @tc.desc: Test IsAppKioskAllowedQuery::QueryPolicy reports the app outside the kiosk whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(IsAppKioskAllowedQueryTest, QueryPolicy_AppNotAllowed_ReturnsFalse, TestSize.Level1)
{
    IsAppKioskAllowedQuery query;
    std::string policyData = BuildKioskPolicy({ "com.test.a" });
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.test.not.exists");
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}

/**
 * @tc.name: QueryPolicy_EmptyPolicy_ReturnsFalse
 * @tc.desc: Test IsAppKioskAllowedQuery::QueryPolicy with no whitelist configured.
 * @tc.type: FUNC
 */
HWTEST_F(IsAppKioskAllowedQueryTest, QueryPolicy_EmptyPolicy_ReturnsFalse, TestSize.Level1)
{
    IsAppKioskAllowedQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("com.test.a");
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    EXPECT_FALSE(reply.ReadBool());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
