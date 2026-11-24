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

#include "allowed_odd_burn_usb_devices_for_account_query.h"

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

namespace {
const int32_t VID_1 = 111;
const int32_t PID_1 = 222;
const int32_t VID_2 = 333;
const int32_t PID_2 = 444;
const std::string SERIAL_1 = "serial1";
const int32_t TEST_ACCOUNT_ID = 101;
} // namespace

class AllowedOddBurnUsbDevicesForAccountQueryTest : public testing::Test {
protected:
    void SetUp() override
    {
        query_ = std::make_shared<AllowedOddBurnUsbDevicesForAccountQuery>();
    }

    void TearDown() override
    {
        query_.reset();
    }

    std::shared_ptr<AllowedOddBurnUsbDevicesForAccountQuery> query_;
};

/**
 * @tc.name: GetPolicyName_Default_Success
 * @tc.desc: Test GetPolicyName returns account-level odd burn policy name.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, GetPolicyName_Default_Success, TestSize.Level1)
{
    EXPECT_EQ(query_->GetPolicyName(), PolicyName::POLICY_ALLOWED_ODD_BURN_USB_DEVICES_FOR_ACCOUNT);
}

/**
 * @tc.name: GetPermission_AnyAdminType_Success
 * @tc.desc: Test GetPermission returns ENTERPRISE_MANAGE_USB for different admin types.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, GetPermission_AnyAdminType_Success, TestSize.Level1)
{
    EXPECT_EQ(query_->GetPermission(IPlugin::PermissionType::SUPER_DEVICE_ADMIN, ""),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    EXPECT_EQ(query_->GetPermission(IPlugin::PermissionType::NORMAL_DEVICE_ADMIN, "tag"),
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
}

/**
 * @tc.name: QueryPolicy_ValidWhitelist_Success
 * @tc.desc: Test QueryPolicy writes whitelist devices into reply parcel.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, QueryPolicy_ValidWhitelist_Success, TestSize.Level1)
{
    std::string policyData = R"([
        {"vendorId":111, "productId":222, "serial":"serial1"},
        {"vendorId":333, "productId":444, "serial":""}
    ])";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);

    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_EQ(devices.size(), 2u);
    EXPECT_EQ(devices[0].GetVendorId(), VID_1);
    EXPECT_EQ(devices[0].GetProductId(), PID_1);
    EXPECT_EQ(devices[0].GetSerial(), SERIAL_1);
    EXPECT_EQ(devices[1].GetVendorId(), VID_2);
    EXPECT_EQ(devices[1].GetProductId(), PID_2);
}

/**
 * @tc.name: QueryPolicy_EmptyPolicy_EmptyListSuccess
 * @tc.desc: Test QueryPolicy with empty policy data returns empty device list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, QueryPolicy_EmptyPolicy_EmptyListSuccess, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);

    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_TRUE(devices.empty());
}

/**
 * @tc.name: QueryPolicy_EmptyJsonArray_EmptyListSuccess
 * @tc.desc: Test QueryPolicy with empty JSON array returns empty device list.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, QueryPolicy_EmptyJsonArray_EmptyListSuccess, TestSize.Level1)
{
    std::string policyData = "[]";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, TEST_ACCOUNT_ID);
    ASSERT_EQ(ret, ERR_OK);

    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<OddBurnUsbDevice> devices;
    ASSERT_TRUE(ArrayOddBurnUsbDeviceSerializer::GetInstance()->ReadRawDataFromParcel(reply, devices));
    EXPECT_TRUE(devices.empty());
}

/**
 * @tc.name: QueryPolicy_InvalidJson_Fail
 * @tc.desc: Test QueryPolicy returns EXECUTE_TIME_OUT when policy data is invalid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, QueryPolicy_InvalidJson_Fail, TestSize.Level1)
{
    std::string policyData = "invalid_json";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: QueryPolicy_NotArrayJson_Fail
 * @tc.desc: Test QueryPolicy returns EXECUTE_TIME_OUT when policy data is not an array.
 * @tc.type: FUNC
 */
HWTEST_F(AllowedOddBurnUsbDevicesForAccountQueryTest, QueryPolicy_NotArrayJson_Fail, TestSize.Level1)
{
    std::string policyData = R"({"vendorId":111})";
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = query_->QueryPolicy(policyData, data, reply, TEST_ACCOUNT_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
