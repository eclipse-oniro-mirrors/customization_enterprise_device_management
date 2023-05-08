/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "device_info_plugin_test.h"
#include "iplugin_template.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DeviceInfoPluginTest::SetUpTestCase(void)
{
    Utils::SetEdmInitialEnv();
}

void DeviceInfoPluginTest::TearDownTestCase(void)
{
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestGetDeviceSerial
 * @tc.desc: Test GetDeviceSerialPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceSerial, TestSize.Level1)
{
    plugin_ = GetDeviceSerialPlugin::GetPlugin();
    std::string policyData{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDisplayVersion
 * @tc.desc: Test GetDisplayVersionPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDisplayVersion, TestSize.Level1)
{
    plugin_ = GetDisplayVersionPlugin::GetPlugin();
    std::string policyData{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS