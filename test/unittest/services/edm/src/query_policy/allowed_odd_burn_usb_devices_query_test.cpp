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
#include "allowed_odd_burn_usb_devices_query.h"
#include "is_allowed_odd_burn_query.h"
#undef private
#undef protected

#include "array_odd_burn_usb_device_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "odd_burn_usb_device.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const int32_t VID_1 = 111;
const int32_t PID_1 = 222;
const int32_t VID_2 = 333;
const int32_t PID_2 = 444;
const std::string SERIAL_1 = "serial1";

class AllowedOddBurnUsbDevicesQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<AllowedOddBurnUsbDevicesQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<AllowedOddBurnUsbDevicesQuery> query_;
};

/**
 * @tc.name: TestGetPolicyName
 * @tc.desc: Test GetPolicyName returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestGetPolicyName, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES);
}

/**
 * @tc.name: TestGetPermission
 * @tc.desc: Test GetPermission returns correct permission.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestGetPermission, TestSize.Level1)
{
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    std::string permission2 = query_->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "test_tag");
    EXPECT_EQ(permission2, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
}

/**
 * @tc.name: TestQueryPolicySuc
 * @tc.desc: Test QueryPolicy with valid JSON containing devices.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestQueryPolicySuc, TestSize.Level1)
{
    std::string policyData = R"([
        {"vendorId":111, "productId":222, "serial":"serial1"},
        {"vendorId":333, "productId":444, "serial":""}
    ])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_EQ(devices.size(), 2u);
}

/**
 * @tc.name: TestQueryPolicyEmpty
 * @tc.desc: Test QueryPolicy with empty policy data.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestQueryPolicyEmpty, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);

    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_TRUE(devices.empty());
}

/**
 * @tc.name: TestQueryPolicyInvalidJson
 * @tc.desc: Test QueryPolicy with invalid JSON causes Deserialize failure.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestQueryPolicyInvalidJson, TestSize.Level1)
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
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestQueryPolicyNotArray, TestSize.Level1)
{
    std::string policyData = R"({"vendorId":111,"productId":222})";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: TestQueryPolicyMissingFields
 * @tc.desc: Test QueryPolicy with JSON missing required fields.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesQueryTest, TestQueryPolicyMissingFields, TestSize.Level1)
{
    std::string policyData = R"([{"vendorId":111}])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

class IsAllowedOddBurnQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<IsAllowedOddBurnQuery>();
    }

    void TearDown() override
    {
        query_ = nullptr;
    }

    std::shared_ptr<IsAllowedOddBurnQuery> query_;
};

/**
 * @tc.name: TestIsAllowedGetPolicyName
 * @tc.desc: Test IsAllowedOddBurnQuery::GetPolicyName returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedGetPolicyName, TestSize.Level1)
{
    std::string policyName = query_->GetPolicyName();
    EXPECT_EQ(policyName, PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES);
}

/**
 * @tc.name: TestIsAllowedGetPermission
 * @tc.desc: Test IsAllowedOddBurnQuery::GetPermission returns correct permission.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedGetPermission, TestSize.Level1)
{
    std::string permission = query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, "");
    EXPECT_EQ(permission, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
}

/**
 * @tc.name: TestIsAllowedQueryPolicyMatch
 * @tc.desc: Test QueryPolicy when device matches whitelist (with serial).
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedQueryPolicyMatch, TestSize.Level1)
{
    std::string policyData = R"([
        {"vendorId":111, "productId":222, "serial":"serial1"}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VID_1);
    data.WriteInt32(PID_1);
    data.WriteString(SERIAL_1);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);
    bool isAllowed = reply.ReadBool();
    EXPECT_TRUE(isAllowed);
}

/**
 * @tc.name: TestIsAllowedQueryPolicyNoMatch
 * @tc.desc: Test QueryPolicy when device does not match whitelist.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedQueryPolicyNoMatch, TestSize.Level1)
{
    std::string policyData = R"([
        {"vendorId":111, "productId":222, "serial":"serial1"}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VID_2);
    data.WriteInt32(PID_2);
    data.WriteString("other");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);
    bool isAllowed = reply.ReadBool();
    EXPECT_FALSE(isAllowed);
}

/**
 * @tc.name: TestIsAllowedQueryPolicyMatchWithoutSerial
 * @tc.desc: Test QueryPolicy when whitelist device has no serial, match by vid/pid only.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedQueryPolicyMatchWithoutSerial, TestSize.Level1)
{
    std::string policyData = R"([
        {"vendorId":111, "productId":222}
    ])";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VID_1);
    data.WriteInt32(PID_1);
    data.WriteString("any_serial");

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);
    bool isAllowed = reply.ReadBool();
    EXPECT_TRUE(isAllowed);
}

/**
 * @tc.name: TestIsAllowedQueryPolicyEmptyWhitelist
 * @tc.desc: Test QueryPolicy when whitelist is empty, should be allowed.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedQueryPolicyEmptyWhitelist, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VID_1);
    data.WriteInt32(PID_1);
    data.WriteString(SERIAL_1);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, ERR_OK);
    bool isAllowed = reply.ReadBool();
    EXPECT_TRUE(isAllowed);
}

/**
 * @tc.name: TestIsAllowedQueryPolicyInvalidJson
 * @tc.desc: Test QueryPolicy with invalid JSON causes failure.
 * @tc.type: FUNC
 */
HWTEST_F(IsAllowedOddBurnQueryTest, TestIsAllowedQueryPolicyInvalidJson, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VID_1);
    data.WriteInt32(PID_1);
    data.WriteString(SERIAL_1);

    ErrCode ret = query_->QueryPolicy(policyData, data, reply, EdmConstants::DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);

    int32_t result = reply.ReadInt32();
    EXPECT_EQ(result, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
