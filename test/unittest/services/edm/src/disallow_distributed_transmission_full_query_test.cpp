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
const std::string TEST_PERMISSION_TAG_VERSION_11 = "version_11";
const std::string TEST_PERMISSION_TAG_VERSION_12 = "version_12";
const std::string TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS = "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS";

class DisallowDistributedTransmissionFullQueryTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowDistributedTransmissionFullQueryTest::SetUp() {}

void DisallowDistributedTransmissionFullQueryTest::TearDown() {}

void DisallowDistributedTransmissionFullQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowDistributedTransmissionFullQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullQuery001
 * @tc.desc: Test DisallowDistributedTransmissionFullQuery::QueryPolicy function with policy set to true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullQueryTest, TestDisallowDistributedTransmissionFullQuery001, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullQuery002
 * @tc.desc: Test DisallowDistributedTransmissionFullQuery::QueryPolicy function with policy set to false.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullQueryTest, TestDisallowDistributedTransmissionFullQuery002, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{"false"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullQuery003
 * @tc.desc: Test DisallowDistributedTransmissionFullQuery::QueryPolicy function with empty policy.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullQueryTest, TestDisallowDistributedTransmissionFullQuery003, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL);
    ASSERT_NE(queryObj, nullptr);
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = queryObj->QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestDisallowDistributedTransmissionFullQuery004
 * @tc.desc: Test DisallowDistributedTransmissionFullQuery GetPolicyName and GetPermission function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowDistributedTransmissionFullQueryTest, TestDisallowDistributedTransmissionFullQuery004, TestSize.Level1)
{
    std::shared_ptr<IPolicyQuery> queryObj =
        PolicyQueryFactory::CreateQuery(EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL);
    ASSERT_NE(queryObj, nullptr);
    std::string permissionTag = TEST_PERMISSION_TAG_VERSION_11;
    ASSERT_TRUE(queryObj->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, permissionTag)
        == TEST_PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    ASSERT_TRUE(queryObj->GetPolicyName() == PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
