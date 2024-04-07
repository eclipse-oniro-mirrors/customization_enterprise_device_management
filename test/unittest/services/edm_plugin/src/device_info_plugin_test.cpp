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

#include "edm_data_ability_utils_mock.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DeviceInfoPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DeviceInfoPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
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

/**
 * @tc.name: TestGetDeviceInfoSyncWithDeviceName
 * @tc.desc: Test GetDeviceInfoPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithDeviceName, TestSize.Level1)
{
    plugin_ = GetDeviceInfoPlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::DeviceInfo::DEVICE_NAME);
    EdmDataAbilityUtils::SetResult("test Failed");
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestGetDeviceInfoSyncWithDeviceNameEmpty
 * @tc.desc: Test OnPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithDeviceNameEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetDeviceInfoPlugin::GetPlugin();
    std::string policyValue;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::DeviceInfo::DEVICE_NAME);
    EdmDataAbilityUtils::SetResult("test value nullptr");
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: TestGetDeviceInfoSyncWithDeviceNameSuc
 * @tc.desc: Test OnPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithDeviceNameSuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = GetDeviceInfoPlugin::GetPlugin();
    std::string policyValue;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::DeviceInfo::DEVICE_NAME);
    EdmDataAbilityUtils::SetResult("test success");
    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_TRUE(code == ERR_OK);
}

/**
 * @tc.name: TestGetDeviceInfoSyncWithDeviceSerial
 * @tc.desc: Test GetDeviceInfoPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithDeviceSerial, TestSize.Level1)
{
    plugin_ = GetDeviceInfoPlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::DeviceInfo::DEVICE_SERIAL);
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDeviceInfoSyncWithSimInfo
 * @tc.desc: Test GetDeviceInfoPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithSimInfo, TestSize.Level1)
{
    plugin_ = GetDeviceInfoPlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::DeviceInfo::SIM_INFO);
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
#ifdef TELEPHONY_CORE_EDM_ENABLE_TEST
    ASSERT_TRUE(ret == ERR_OK);
#else
    ASSERT_TRUE(ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
#endif
}

/**
 * @tc.name: TestGetDeviceInfoSyncWithInvalidLabel
 * @tc.desc: Test GetDeviceInfoPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceInfoPluginTest, TestGetDeviceInfoSyncWithInvalidLabel, TestSize.Level1)
{
    plugin_ = GetDeviceInfoPlugin::GetPlugin();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("invalid");
    ErrCode ret = plugin_->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS