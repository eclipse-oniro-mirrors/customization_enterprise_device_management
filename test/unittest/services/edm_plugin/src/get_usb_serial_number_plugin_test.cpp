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
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "get_usb_serial_number_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_BUS_NUM = 1;
const int32_t TEST_DEV_ADDRESS = 1;
const int32_t TEST_BUS_NUM_NEGATIVE = -1;
const int32_t TEST_DEV_ADDRESS_NEGATIVE = -1;

class GetUsbSerialNumberPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void GetUsbSerialNumberPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetUsbSerialNumberPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicyGetDevicesFail
 * @tc.desc: Test GetUsbSerialNumberPlugin::OnGetPolicy when UsbSrvClient::GetDevices fails.
 * @tc.type: FUNC
 */
HWTEST_F(GetUsbSerialNumberPluginTest, TestOnGetPolicyGetDevicesFail, TestSize.Level1)
{
    auto plugin = std::make_shared<GetUsbSerialNumberPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(TEST_BUS_NUM_NEGATIVE);
    data.WriteInt32(TEST_DEV_ADDRESS_NEGATIVE);
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyWithOneParams
 * @tc.desc: Test GetUsbSerialNumberPlugin::OnGetPolicy with busNum=1 and devAddress=1.
 * @tc.type: FUNC
 */
HWTEST_F(GetUsbSerialNumberPluginTest, TestOnGetPolicyWithOneParams, TestSize.Level1)
{
    auto plugin = std::make_shared<GetUsbSerialNumberPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(TEST_BUS_NUM);
    data.WriteInt32(TEST_DEV_ADDRESS);
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
#ifdef FEATURE_PC_ONLY
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
#else
    ASSERT_EQ(ret, ERR_OK);
#endif
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS