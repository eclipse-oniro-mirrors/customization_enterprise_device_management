/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "disallowed_usb_devices_plugin.h"
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
const std::string TEST_POLICY_DATA = "[{\"baseClass\":3,\"subClass\":1,\"protocol\":2,\"isDeviceType\":false}]";
const std::string TEST_CURRENT_DATA = "[{\"baseClass\":8,\"subClass\":3,\"protocol\":2,\"isDeviceType\":false}]";

class DisallowedUsbDevicesPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowedUsbDevicesPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedUsbDevicesPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyDataSetAllEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data and current data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyDataSetAllEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicySetCurrentDataEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when current data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicySetCurrentDataEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicySetDataEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicySetDataEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: TestOnHandlePolicySetDataSame
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is same as current data
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicySetDataSame, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: TestOnHandlePolicySetDataDiff
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is different from current data
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicySetDataDiff, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_CURRENT_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyDataRemoveAllEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data and current data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyDataRemoveAllEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveCurrentDataEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when current data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyRemoveCurrentDataEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"", "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_FALSE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveDataEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is empty
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyRemoveDataEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    data.WriteUint32(0);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_POLICY_DATA);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveDataSame
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is same as current data
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyRemoveDataSame, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_POLICY_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(handlePolicyData.policyData.empty());
    ASSERT_TRUE(handlePolicyData.isChanged);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveDataDiff
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnHandlePolicy when data is different from current data
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnHandlePolicyRemoveDataDiff, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOWED_USB_DEVICES);
    MessageParcel data;
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    usbDeviceTypes.emplace_back(type);
    data.WriteUint32(usbDeviceTypes.size());
    std::for_each(usbDeviceTypes.begin(), usbDeviceTypes.end(), [&](const auto usbDeviceType) {
        usbDeviceType.Marshalling(data);
    });
    MessageParcel reply;
    HandlePolicyData handlePolicyData{TEST_CURRENT_DATA, "", false};
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string result;
    std::copy_if(handlePolicyData.policyData.begin(), handlePolicyData.policyData.end(),
        std::back_inserter(result), [](char c) {
        return !std::isspace(static_cast<unsigned char>(c));
    });
    ASSERT_TRUE(result == TEST_CURRENT_DATA);
}

/**
 * @tc.name: TestOnGetPolicyEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnGetPolicy function when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnGetPolicyEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnGetPolicySuc
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnGetPolicy function when data is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnGetPolicySuc, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::string policyData{TEST_POLICY_DATA};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemovePolicyEmpty
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnAdminRemove function when policy is true.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnAdminRemovePolicyEmpty, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::string adminName{"testAdminName"};
    std::string policyData{""};
    std::string mergeData;
    ErrCode ret = plugin->OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveFalse
 * @tc.desc: Test DisallowedUsbDevicesPluginTest::OnAdminRemove function when policy is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginTest, TestOnAdminRemoveHasPolicy, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallowedUsbDevicesPlugin::GetPlugin();
    std::string adminName{"testAdminName"};
    std::string policyData{TEST_POLICY_DATA};
    std::string mergeData;
    ErrCode ret = plugin->OnAdminRemove(adminName, policyData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS