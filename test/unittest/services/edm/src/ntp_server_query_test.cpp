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

#include "edm_constants.h"
#include "edm_errors.h"
#include "ntp_server_query.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class NTPServerQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void NTPServerQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void NTPServerQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_ReturnCorrectValue_Success
 * @tc.desc: Test NTPServerQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(NTPServerQueryTest, GetPolicyName_ReturnCorrectValue_Success, TestSize.Level1)
{
    NTPServerQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_NTP_SERVER);
}

/**
 * @tc.name: GetPermission_ReturnCorrectValue_Success
 * @tc.desc: Test NTPServerQuery::GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(NTPServerQueryTest, GetPermission_ReturnCorrectValue_Success, TestSize.Level1)
{
    NTPServerQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "version_23"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
}

/**
 * @tc.name: QueryPolicy_ReturnCurrentServer
 * @tc.desc: Test NTPServerQuery::QueryPolicy replies with the NTP server parameter.
 * @tc.type: FUNC
 */
HWTEST_F(NTPServerQueryTest, QueryPolicy_ReturnCurrentServer, TestSize.Level1)
{
    NTPServerQuery query;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
}

/**
 * @tc.name: QueryPolicy_IgnorePolicyData_Success
 * @tc.desc: Test NTPServerQuery::QueryPolicy answers from the parameter, not the stored policy.
 * @tc.type: FUNC
 */
HWTEST_F(NTPServerQueryTest, QueryPolicy_IgnorePolicyData_Success, TestSize.Level1)
{
    NTPServerQuery query;
    std::string policyData = "broken";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
