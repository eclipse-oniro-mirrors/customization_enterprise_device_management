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

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "generic_policy_query.h"
#include "ipolicy_query.h"
#include "policy_query_factory.h"
#include "utils.h"

// The factory always returns GenericPolicyQuery for BOOL policies (CreateGenericQuery).
// OpenHarmony builds with -fno-rtti, so tests downcast with static_pointer_cast.

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
// SpecificPermission config ignores the permission tag; an empty tag is used explicitly.
const std::string TEST_PERMISSION_TAG_EMPTY = "";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_TELEPHONY =
    "ohos.permission.ENTERPRISE_MANAGE_TELEPHONY";

class SwitchDatacardQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SwitchDatacardQueryTest::SetUp() {}

void SwitchDatacardQueryTest::TearDown() {}

void SwitchDatacardQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SwitchDatacardQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestSwitchDatacardQueryTrue
 * @tc.desc: Query the non-default data SIM internet policy when it is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(SwitchDatacardQueryTest, TestSwitchDatacardQueryTrue, TestSize.Level1)
{
    auto queryObj = std::static_pointer_cast<GenericPolicyQuery>(
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::SWITCH_DATACARD_DISABLE));
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestSwitchDatacardQueryFalse
 * @tc.desc: Query the non-default data SIM internet policy when it is enabled.
 * @tc.type: FUNC
 */
HWTEST_F(SwitchDatacardQueryTest, TestSwitchDatacardQueryFalse, TestSize.Level1)
{
    auto queryObj = std::static_pointer_cast<GenericPolicyQuery>(
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::SWITCH_DATACARD_DISABLE));
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = true;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestSwitchDatacardQueryEmpty
 * @tc.desc: Query the policy when it has not been set returns false.
 * @tc.type: FUNC
 */
HWTEST_F(SwitchDatacardQueryTest, TestSwitchDatacardQueryEmpty, TestSize.Level1)
{
    auto queryObj = std::static_pointer_cast<GenericPolicyQuery>(
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::SWITCH_DATACARD_DISABLE));
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = true;
    ASSERT_TRUE(reply.ReadBool(result));
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestSwitchDatacardQueryPermission
 * @tc.desc: Verify the query permission and policy name of the new policy.
 * @tc.type: FUNC
 */
HWTEST_F(SwitchDatacardQueryTest, TestSwitchDatacardQueryPermission, TestSize.Level1)
{
    auto queryObj = std::static_pointer_cast<GenericPolicyQuery>(
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::SWITCH_DATACARD_DISABLE));
    ASSERT_NE(queryObj, nullptr);
    std::string permissionTag = TEST_PERMISSION_TAG_EMPTY;
    ASSERT_EQ(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag),
        TEST_PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    ASSERT_EQ(queryObj->GetPolicyName(), PolicyName::POLICY_DISABLE_SWITCH_DATACARD);
}

/**
 * @tc.name: TestUnknownPolicyCodeQuery
 * @tc.desc: An unknown policy code has no query object. Note the 801 returned by the unified
 *           restrictions API comes from the missing plugin registration for the code, not from
 *           the query path itself.
 * @tc.type: FUNC
 */
HWTEST_F(SwitchDatacardQueryTest, TestUnknownPolicyCodeQuery, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(static_cast<uint32_t>(EdmInterfaceCode::POLICY_CODE_END + 999));
    ASSERT_EQ(queryObj, nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
