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

#define protected public
#include "disallowed_permissive_usb_devices_plugin.h"
#undef protected

#include <gtest/gtest.h>
#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t BASE_CLASS = 3;
const int32_t SUB_CLASS = 1;
const int32_t PROTOCOL = 2;
const std::string TEST_POLICY_DATA =
    "[{\"baseClass\":3,\"subClass\":1,\"protocol\":2,\"isDeviceType\":false,\"isDeviceTypeAllMatch\":false}]";
const std::string TEST_CURRENT_DATA =
    "[{\"baseClass\":8,\"subClass\":3,\"protocol\":2,\"isDeviceType\":false,\"isDeviceTypeAllMatch\":false}]";

class DisallowedPermissiveUsbDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedPermissiveUsbDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedPermissiveUsbDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetAllEmpty_Success
 * @tc.desc: Test OnHandlePolicy when data and current data is empty for SET operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetAllEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "");
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetCurrentDataEmpty_Success
 * @tc.desc: Test OnHandlePolicy when current data is empty for SET operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetCurrentDataEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataEmpty_Success
 * @tc.desc: Test OnHandlePolicy when data is empty for SET operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataSame_Success
 * @tc.desc: Test OnHandlePolicy when data is same as current data for SET operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataSame_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataDiff_Success
 * @tc.desc: Test OnHandlePolicy when data is different from current data for SET operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_SetDataDiff_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_CURRENT_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveAllEmpty_Success
 * @tc.desc: Test OnHandlePolicy when data and current data is empty for REMOVE operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveAllEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "");
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveCurrentDataEmpty_Success
 * @tc.desc: Test OnHandlePolicy when current data is empty for REMOVE operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveCurrentDataEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "");
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataEmpty_Success
 * @tc.desc: Test OnHandlePolicy when data is empty for REMOVE operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataEmpty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataSame_Success
 * @tc.desc: Test OnHandlePolicy when data is same as current data for REMOVE operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataSame_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData == "");
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataDiff_Success
 * @tc.desc: Test OnHandlePolicy when data is different from current data for REMOVE operation.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnHandlePolicy_RemoveDataDiff_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_CURRENT_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_CURRENT_DATA);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnGetPolicy_Empty_Success
 * @tc.desc: Test OnGetPolicy function when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnGetPolicy_Empty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnGetPolicy_Success
 * @tc.desc: Test OnGetPolicy function when data is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnGetPolicy_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::string policyData{TEST_POLICY_DATA};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnAdminRemove_Empty_Success
 * @tc.desc: Test OnAdminRemove function when policy is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnAdminRemove_Empty_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::string adminName{"testAdminName"};
    std::string policyData{""};
    std::string mergeData;
    ErrCode ret = plugin->OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_OnAdminRemove_HasPolicy_Success
 * @tc.desc: Test OnAdminRemove function when policy has data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_OnAdminRemove_HasPolicy_Success, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedPermissiveUsbDevicesPlugin::GetPlugin();
    std::string adminName{"testAdminName"};
    std::string policyData{TEST_POLICY_DATA};
    std::string mergeData;
    ErrCode ret = plugin->OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_GetPolicyName_Correct
 * @tc.desc: Test GetPolicyName returns correct policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_GetPolicyName_Correct, TestSize.Level1)
{
    DisallowedPermissiveUsbDevicesPlugin plugin;
    const char* policyName = plugin.GetPolicyName();
    ASSERT_STREQ(policyName, PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_GetPluginName_Correct
 * @tc.desc: Test GetPluginName returns correct plugin name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_GetPluginName_Correct, TestSize.Level1)
{
    DisallowedPermissiveUsbDevicesPlugin plugin;
    std::string pluginName = plugin.GetPluginName();
    ASSERT_EQ(pluginName, "DisallowedPermissiveUsbDevicesPlugin");
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_GetDisallowedUsbDevicesTypeMaxSize_Correct
 * @tc.desc: Test GetDisallowedUsbDevicesTypeMaxSize returns correct max size.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_GetDisallowedUsbDevicesTypeMaxSize_Correct, TestSize.Level1)
{
    DisallowedPermissiveUsbDevicesPlugin plugin;
    uint32_t maxSize = plugin.GetDisallowedUsbDevicesTypeMaxSize();
    ASSERT_EQ(maxSize, EdmConstants::DISALLOWED_PERMISSIVE_USB_DEVICES_TYPES_MAX_SIZE);
}

/**
 * @tc.name: DisallowedPermissiveUsbDevicesPlugin_GetConflictPolicyName_Correct
 * @tc.desc: Test GetConflictPolicyName returns correct conflict policy name.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedPermissiveUsbDevicesPluginTest,
    DisallowedPermissiveUsbDevicesPlugin_GetConflictPolicyName_Correct, TestSize.Level1)
{
    DisallowedPermissiveUsbDevicesPlugin plugin;
    const char* conflictPolicyName = plugin.GetConflictPolicyName();
    ASSERT_STREQ(conflictPolicyName, PolicyName::POLICY_DISALLOWED_USB_DEVICES);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
