/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public
#include "set_device_name_plugin.h"
#undef private

#include <gtest/gtest.h>

#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl_mock.h"
#include "external_manager_factory_mock.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetValueForAccountPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetValueForAccountPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetValueForAccountPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicy_001
 * @tc.desc: Test OnHandlePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_001, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString("test");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 100);
    EXPECT_EQ(code, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicy_002
 * @tc.desc: Test OnHandlePolicy function with empty data.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_002, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString("");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 100);
    EXPECT_EQ(code, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_003
 * @tc.desc: Test OnHandlePolicy function with data exceeding max length.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_003, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString(
        "test1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 100);
    EXPECT_EQ(code, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_InvalidUserId_FAIL
 * @tc.desc: Test OnHandlePolicy function with invalid userId.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_InvalidUserId_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString("test");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 101);
    EXPECT_EQ(code, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicy_GetUserIdFail_FAIL
 * @tc.desc: Test OnHandlePolicy function when get userId fail.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_GetUserIdFail_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString("test");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, GetCurrentUserId).Times(1).WillOnce(Return(-1));
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 100);
    EXPECT_EQ(code, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicy_UpdateSettingsData_FAIL
 * @tc.desc: Test OnHandlePolicy function when update settings data fail.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnHandlePolicy_UpdateSettingsData_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    MessageParcel data;
    data.WriteString("test");
    MessageParcel reply;
    HandlePolicyData handlePolicyData;
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");
    ErrCode code = plugin.OnHandlePolicy(0, data, reply, handlePolicyData, 100);
    EXPECT_EQ(code, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicy_001
 * @tc.desc: Test OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnGetPolicy_001, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = std::make_shared<SetDeviceNamePlugin>();
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;

    ErrCode code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);

    EdmDataAbilityUtils::SetResult("test success");
    code = plugin->OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(code, ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicy_InvalidUserId_FAIL
 * @tc.desc: Test OnGetPolicy function with invalid userId.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnGetPolicy_InvalidUserId_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    int32_t id = 101;
    ErrCode code = plugin.OnGetPolicy(policyValue, data, reply, id);
    EXPECT_EQ(code, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicy_GetUserIdFail_FAIL
 * @tc.desc: Test OnGetPolicy function when get userId fail.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnGetPolicy_GetUserIdFail_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;
    int32_t id = 100;
    auto factory = std::make_shared<ExternalManagerFactoryMock>();
    auto osAccountMgrMock = std::make_shared<EdmOsAccountManagerImplMock>();
    plugin.externalManagerFactory_ = factory;
    EXPECT_CALL(*factory, CreateOsAccountManager).Times(1).WillOnce(Return(osAccountMgrMock));
    EXPECT_CALL(*osAccountMgrMock, GetCurrentUserId).Times(1).WillOnce(Return(-1));
    ErrCode code = plugin.OnGetPolicy(policyValue, data, reply, id);
    EXPECT_EQ(code, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicy_GetStringFromSettingsDataShare_FAIL
 * @tc.desc: Test OnGetPolicy function when GetStringFromSettingsDataShare fails.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestOnGetPolicy_GetStringFromSettingsDataShare_FAIL, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string policyValue{"TestString"};
    MessageParcel data;
    MessageParcel reply;

    EdmDataAbilityUtils::SetResult("test Failed");
    ErrCode code = plugin.OnGetPolicy(policyValue, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(code, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

#if defined(TELEPHONY_EDM_ENABLE) && defined(WIFI_EDM_ENABLE)
/**
 * @tc.name: TestUpdateHotspotNameIfNeed_NonMainUser
 * @tc.desc: Test UpdateHotspotNameIfNeed when userId is not MAIN_USER_ID.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestUpdateHotspotNameIfNeed_NonMainUser, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "testDeviceName";
    int32_t userId = 101;
    ErrCode code = plugin.UpdateHotspotNameIfNeed(value, userId);
    EXPECT_EQ(code, ERR_OK);
}

/**
 * @tc.name: TestGetSubstringByBytes_EmptyString
 * @tc.desc: Test GetSubstringByBytes with empty string.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_EmptyString, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "";
    size_t size = 10;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: TestGetSubstringByBytes_ShortString
 * @tc.desc: Test GetSubstringByBytes when string length <= size.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_ShortString, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "test";
    size_t size = 10;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "test");
}

/**
 * @tc.name: TestGetSubstringByBytes_ASCIIString
 * @tc.desc: Test GetSubstringByBytes with ASCII string.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_ASCIIString, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "abcdefghij";
    size_t size = 5;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "abcde");
}

/**
 * @tc.name: TestGetSubstringByBytes_ChineseString
 * @tc.desc: Test GetSubstringByBytes with Chinese UTF-8 string (3 bytes per char).
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_ChineseString, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "测试中文截取";
    size_t size = 6;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "测试");
}

/**
 * @tc.name: TestGetSubstringByBytes_MixedString
 * @tc.desc: Test GetSubstringByBytes with mixed ASCII and Chinese characters.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_MixedString, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "abc测试def";
    size_t size = 6;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "abc测");
}

/**
 * @tc.name: TestGetSubstringByBytes_OverBoundary
 * @tc.desc: Test GetSubstringByBytes when next char exceeds boundary.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_OverBoundary, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "测试测试";
    size_t size = 5;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "测");
}

/**
 * @tc.name: TestGetSubstringByBytes_TwoByteChar
 * @tc.desc: Test GetSubstringByBytes with 2-byte UTF-8 characters.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_TwoByteChar, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "éééééé";
    size_t size = 4;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "éé");
}

/**
 * @tc.name: TestGetSubstringByBytes_FourByteChar
 * @tc.desc: Test GetSubstringByBytes with 4-byte UTF-8 characters.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestGetSubstringByBytes_FourByteChar, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "𠮷𠮷𠮷";
    size_t size = 4;
    std::string result = plugin.GetSubstringByBytes(value, size);
    EXPECT_EQ(result, "𠮷");
}

/**
 * @tc.name: TestPrepareHotspotConfig_NormalCase
 * @tc.desc: Test PrepareHotspotConfig with normal device name.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_NormalCase, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "NewDeviceName";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("OldDeviceName");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_TRUE(needUpdate);
}

/**
 * @tc.name: TestPrepareHotspotConfig_CloningCase
 * @tc.desc: Test PrepareHotspotConfig when hotspot is cloning.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_CloningCase, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "NewDeviceName";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("OldCloudClone");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_FALSE(needUpdate);
}

/**
 * @tc.name: TestPrepareHotspotConfig_SameName
 * @tc.desc: Test PrepareHotspotConfig when name unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_SameName, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "SameDeviceName";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("SameDeviceName");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_FALSE(needUpdate);
}

/**
 * @tc.name: TestPrepareHotspotConfig_LongName
 * @tc.desc: Test PrepareHotspotConfig with name exceeding 30 bytes.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_LongName, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "ThisIsAVeryLongDeviceNameThatExceedsThirtyBytes";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("OldName");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_TRUE(needUpdate);
    std::string newSsid = hotspotConfig.GetSsid();
    EXPECT_TRUE(newSsid.length() <= 30);
    EXPECT_EQ(newSsid.substr(newSsid.length() - 3), "...");
}

/**
 * @tc.name: TestPrepareHotspotConfig_SpaceClone
 * @tc.desc: Test PrepareHotspotConfig with SpaceClone suffix.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_SpaceClone, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "NewDeviceName";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("DeviceSpaceClone");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_FALSE(needUpdate);
}

/**
 * @tc.name: TestPrepareHotspotConfig_SubClone
 * @tc.desc: Test PrepareHotspotConfig with SubClone suffix.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_SubClone, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "NewDeviceName";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("DeviceSubClone");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_FALSE(needUpdate);
}

/**
 * @tc.name: TestPrepareHotspotConfig_LongChineseName
 * @tc.desc: Test PrepareHotspotConfig with long Chinese name.
 * @tc.type: FUNC
 */
HWTEST_F(SetValueForAccountPluginTest, TestPrepareHotspotConfig_LongChineseName, TestSize.Level1)
{
    SetDeviceNamePlugin plugin;
    std::string value = "测试设备名称超过三十字节限制测试测试测试";
    Wifi::HotspotConfig hotspotConfig;
    hotspotConfig.SetSsid("OldName");
    bool needUpdate = false;
    ErrCode code = plugin.PrepareHotspotConfig(value, hotspotConfig, needUpdate);
    EXPECT_EQ(code, ERR_OK);
    EXPECT_TRUE(needUpdate);
    std::string newSsid = hotspotConfig.GetSsid();
    EXPECT_TRUE(newSsid.length() <= 30);
}
#endif
} // namespace TEST
} // namespace EDM
} // namespace OHOS