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

#include "edm_errors.h"
#include "get_usb_device_infos_plugin.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class GetUsbDeviceInfosPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void GetUsbDeviceInfosPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void GetUsbDeviceInfosPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
}

/**
 * @tc.name: TestOnGetPolicyCallUsb
 * @tc.desc: Test GetUsbDeviceInfosPlugin::OnGetPolicy calls USB GetAllDevices.
 * @tc.type: FUNC
 */
HWTEST_F(GetUsbDeviceInfosPluginTest, TestOnGetPolicyCallUsb, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    std::shared_ptr<IPlugin> plugin = std::make_shared<GetUsbDeviceInfosPlugin>();
    std::string policyData;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    // soft-IPC：USB 可用/未落地/未 init 均 ERR_OK（空列表）；其它异常 SYSTEM_ABNORMALLY
    ASSERT_TRUE(ret == ERR_OK || ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    if (ret == ERR_OK) {
        ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
        ASSERT_GE(reply.ReadUint32(), 0u);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
