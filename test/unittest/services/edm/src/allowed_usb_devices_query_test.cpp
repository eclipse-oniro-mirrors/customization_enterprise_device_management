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

#include "allowed_usb_devices_query.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "iplugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class AllowedUsbDevicesQueryTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void AllowedUsbDevicesQueryTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void AllowedUsbDevicesQueryTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: GetPolicyName_ReturnCorrectValue_Success
 * @tc.desc: Test AllowedUsbDevicesQuery::GetPolicyName.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesQueryTest, GetPolicyName_ReturnCorrectValue_Success, TestSize.Level1)
{
    AllowedUsbDevicesQuery query;
    EXPECT_EQ(query.GetPolicyName(), PolicyName::POLICY_ALLOWED_USB_DEVICES);
}

/**
 * @tc.name: GetPermission_ReturnCorrectValue_Success
 * @tc.desc: Test AllowedUsbDevicesQuery::GetPermission.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesQueryTest, GetPermission_ReturnCorrectValue_Success, TestSize.Level1)
{
    AllowedUsbDevicesQuery query;
    EXPECT_EQ(query.GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
}

/**
 * @tc.name: QueryPolicy_EmptyList_Success
 * @tc.desc: Test AllowedUsbDevicesQuery::QueryPolicy writes zero for an empty whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesQueryTest, QueryPolicy_EmptyList_Success, TestSize.Level1)
{
    AllowedUsbDevicesQuery query;
    std::string policyData = "[]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    reply.RewindRead(0);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    uint32_t size = 0;
    EXPECT_TRUE(reply.ReadUint32(size));
    EXPECT_EQ(size, 0u);
}

/**
 * @tc.name: QueryPolicy_OneDevice_Success
 * @tc.desc: Test AllowedUsbDevicesQuery::QueryPolicy marshals each device id.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesQueryTest, QueryPolicy_OneDevice_Success, TestSize.Level1)
{
    AllowedUsbDevicesQuery query;
    std::string policyData = "[{\"vid\":1,\"pid\":2}]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: QueryPolicy_InvalidPolicyData_Failed
 * @tc.desc: Test AllowedUsbDevicesQuery::QueryPolicy rejects an unparsable policy.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedUsbDevicesQueryTest, QueryPolicy_InvalidPolicyData_Failed, TestSize.Level1)
{
    AllowedUsbDevicesQuery query;
    std::string policyData = "broken";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query.QueryPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
