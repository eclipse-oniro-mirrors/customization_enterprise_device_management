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
#define private public
#include "disallowed_usb_devices_plugin_base.h"
#undef private
#undef protected

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "array_usb_device_type_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ipolicy_manager.h"
#include "policy_manager.h"
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

// Mock implementation of DisallowedUsbDevicesPluginBase for testing
class DisallowedUsbDevicesPluginBaseMock : public DisallowedUsbDevicesPluginBase {
public:
    MOCK_METHOD(const char*, GetPolicyName, (), (const, override));
    MOCK_METHOD(uint32_t, GetDisallowedUsbDevicesTypeMaxSize, (), (const, override));
    MOCK_METHOD(const char*, GetConflictPolicyName, (), (const, override));
    MOCK_METHOD(ErrCode, SetDisallowedDevices, (std::vector<USB::UsbDeviceType> &), (override));
    MOCK_METHOD(std::string, GetPluginName, (), (const, override));
    MOCK_METHOD(std::shared_ptr<ArrayUsbDeviceTypeSerializerBase>, GetSerializer, (), (override));
};

class DisallowedUsbDevicesPluginBaseTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);

    void SetUp() override
    {
        mockPlugin_ = std::make_shared<DisallowedUsbDevicesPluginBaseMock>();
        serializer_ = ArrayUsbDeviceTypeSerializer::GetInstance();
    }

    void TearDown() override
    {
        mockPlugin_.reset();
    }

    std::shared_ptr<DisallowedUsbDevicesPluginBaseMock> mockPlugin_;
    std::shared_ptr<ArrayUsbDeviceTypeSerializer> serializer_;
};

void DisallowedUsbDevicesPluginBaseTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowedUsbDevicesPluginBaseTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is original ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_EmptyData_Success
 * @tc.desc: Test OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_EmptyData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_DataTooLarge_Fail
 * @tc.desc: Test OnSetPolicy when data size exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_DataTooLarge_Fail, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    for (uint32_t i = 0; i <= 200; i++) {
        USB::UsbDeviceType type;
        type.baseClass = i % 256;
        type.subClass = (i + 1) % 256;
        type.protocol = (i + 2) % 256;
        type.isDeviceType = false;
        type.isDeviceTypeAllMatch = false;
        data.push_back(type);
    }
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnRemovePolicy_EmptyData_Success
 * @tc.desc: Test OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnRemovePolicy_EmptyData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));

    ErrCode ret = mockPlugin_->OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnRemovePolicy_DataTooLarge_Fail
 * @tc.desc: Test OnRemovePolicy when data size exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnRemovePolicy_DataTooLarge_Fail, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    for (uint32_t i = 0; i <= 200; i++) {
        USB::UsbDeviceType type;
        type.baseClass = i % 256;
        type.subClass = (i + 1) % 256;
        type.protocol = (i + 2) % 256;
        type.isDeviceType = false;
        type.isDeviceTypeAllMatch = false;
        data.push_back(type);
    }
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));

    ErrCode ret = mockPlugin_->OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnBaseGetPolicy_EmptyData_Success
 * @tc.desc: Test OnBaseGetPolicy when policyData is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnBaseGetPolicy_EmptyData_Success, TestSize.Level1)
{
    std::string policyData{""};
    MessageParcel data;
    MessageParcel reply;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));

    ErrCode ret = mockPlugin_->OnBaseGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    uint32_t size = reply.ReadUint32();
    ASSERT_EQ(size, 0);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnBaseGetPolicy_WithData_Success
 * @tc.desc: Test OnBaseGetPolicy when policyData is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnBaseGetPolicy_WithData_Success, TestSize.Level1)
{
    std::string policyData{TEST_POLICY_DATA};
    MessageParcel data;
    MessageParcel reply;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnBaseGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnAdminRemove_EmptyData_Success
 * @tc.desc: Test OnAdminRemove when mergeData is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnAdminRemove_EmptyData_Success, TestSize.Level1)
{
    std::string adminName{"testAdminName"};
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnAdminRemove(adminName, data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnAdminRemove_HasData_Success
 * @tc.desc: Test OnAdminRemove when mergeData has data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnAdminRemove_HasData_Success, TestSize.Level1)
{
    std::string adminName{"testAdminName"};
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> mergeData;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    mergeData.push_back(type);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    ErrCode ret = mockPlugin_->OnAdminRemove(adminName, data, mergeData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_NoConflict_Success
 * @tc.desc: Test OnSetPolicy when no policy conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_NoConflict_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_HasConflict_ReturnConfigurationConflictFailed
 * @tc.desc: Test OnSetPolicy when policy conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_HasConflict_ReturnConfigurationConflictFailed, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISABLE_USB, "true", "true", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISABLE_USB, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_AfterMergeSizeExceedsMax_ReturnParamError
 * @tc.desc: Test OnSetPolicy when merged data size exceeds max size.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_AfterMergeSizeExceedsMax_ReturnParamError, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);

    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;
    for (uint32_t i = 0; i < 200; i++) {
        USB::UsbDeviceType mergeType;
        mergeType.baseClass = (i + 10) % 256;
        mergeType.subClass = (i + 11) % 256;
        mergeType.protocol = (i + 12) % 256;
        mergeType.isDeviceType = false;
        mergeType.isDeviceTypeAllMatch = false;
        mergeData.push_back(mergeType);
    }

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_SetDisallowedDevicesFailed_ReturnError
 * @tc.desc: Test OnSetPolicy when SetDisallowedDevices fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_SetDisallowedDevicesFailed_ReturnError, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(EdmReturnErrCode::SYSTEM_ABNORMALLY));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnSetPolicy_ValidData_Success
 * @tc.desc: Test OnSetPolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnSetPolicy_ValidData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    ErrCode ret = mockPlugin_->OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(currentData.size(), 1);
    EXPECT_EQ(mergeData.size(), 1);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnRemovePolicy_DisallowedEmptyAndCurrentNotEmpty_SetUsbDisabled
 * @tc.desc: Test OnRemovePolicy when disallowed devices is empty but current data is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnRemovePolicy_DisallowedEmptyAndCurrentNotEmpty_SetUsbDisabled, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type1;
    type1.baseClass = BASE_CLASS;
    type1.subClass = SUB_CLASS;
    type1.protocol = PROTOCOL;
    type1.isDeviceType = false;
    type1.isDeviceTypeAllMatch = false;
    data.push_back(type1);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = BASE_CLASS;
    type2.subClass = SUB_CLASS;
    type2.protocol = PROTOCOL;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    ErrCode ret = mockPlugin_->OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnRemovePolicy_SetDisallowedDevicesFailed_ReturnError
 * @tc.desc: Test OnRemovePolicy when SetDisallowedDevices fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnRemovePolicy_SetDisallowedDevicesFailed_ReturnError, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);
    std::vector<USB::UsbDeviceType> currentData;
    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(EdmReturnErrCode::SYSTEM_ABNORMALLY));

    ErrCode ret = mockPlugin_->OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnRemovePolicy_ValidData_Success
 * @tc.desc: Test OnRemovePolicy with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnRemovePolicy_ValidData_Success, TestSize.Level1)
{
    std::vector<USB::UsbDeviceType> data;
    USB::UsbDeviceType type;
    type.baseClass = BASE_CLASS;
    type.subClass = SUB_CLASS;
    type.protocol = PROTOCOL;
    type.isDeviceType = false;
    type.isDeviceTypeAllMatch = false;
    data.push_back(type);

    std::vector<USB::UsbDeviceType> currentData;
    USB::UsbDeviceType type2;
    type2.baseClass = BASE_CLASS;
    type2.subClass = SUB_CLASS;
    type2.protocol = PROTOCOL;
    type2.isDeviceType = false;
    type2.isDeviceTypeAllMatch = false;
    currentData.push_back(type2);

    std::vector<USB::UsbDeviceType> mergeData;

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetDisallowedUsbDevicesTypeMaxSize()).WillRepeatedly(Return(200));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    ErrCode ret = mockPlugin_->OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnAdminRemove_CombineDataEmpty_SetUsbDisabled
 * @tc.desc: Test OnAdminRemove when combined data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnAdminRemove_CombineDataEmpty_SetUsbDisabled, TestSize.Level1)
{
    std::string adminName{"testAdminName"};
    std::vector<USB::UsbDeviceType> data;
    std::vector<USB::UsbDeviceType> mergeData;

    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    ErrCode ret = mockPlugin_->OnAdminRemove(adminName, data, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnOtherServiceStart_DisabledDevicesNotEmpty_CallSetDisallowedDevices
 * @tc.desc: Test OnOtherServiceStart when disallowed devices is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnOtherServiceStart_DisabledDevicesNotEmpty_CallSetDisallowedDevices,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISALLOWED_USB_DEVICES, TEST_POLICY_DATA, TEST_POLICY_DATA, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetPolicyName()).WillRepeatedly(Return(PolicyName::POLICY_DISALLOWED_USB_DEVICES));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));
    EXPECT_CALL(*mockPlugin_, SetDisallowedDevices(_)).WillRepeatedly(Return(ERR_OK));

    mockPlugin_->OnOtherServiceStart(0);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISALLOWED_USB_DEVICES, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_OnOtherServiceStart_DisabledDevicesEmpty_DoNothing
 * @tc.desc: Test OnOtherServiceStart when disallowed devices is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_OnOtherServiceStart_DisabledDevicesEmpty_DoNothing, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetPolicyName()).WillRepeatedly(Return(PolicyName::POLICY_DISALLOWED_USB_DEVICES));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    mockPlugin_->OnOtherServiceStart(0);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_HasConflictPolicy_DisableUsbTrue_ReturnConflict
 * @tc.desc: Test HasConflictPolicy when USB is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_HasConflictPolicy_DisableUsbTrue_ReturnConflict, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISABLE_USB, "true", "true", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));

    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    bool hasConflict = false;
    ErrCode ret = mockPlugin_->HasConflictPolicy(hasConflict, usbDeviceTypes);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(hasConflict);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_DISABLE_USB, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_HasConflictPolicy_AllowedUsbDeviceNotEmpty_ReturnConflict
 * @tc.desc: Test HasConflictPolicy when allowed USB device policy is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_HasConflictPolicy_AllowedUsbDeviceNotEmpty_ReturnConflict, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_ALLOWED_USB_DEVICES, "[{}]", "[{}]", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));

    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    bool hasConflict = false;
    ErrCode ret = mockPlugin_->HasConflictPolicy(hasConflict, usbDeviceTypes);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(hasConflict);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_ALLOWED_USB_DEVICES, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_HasConflictPolicy_ConflictPolicyNotEmpty_ReturnConflict
 * @tc.desc: Test HasConflictPolicy when conflict policy is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_HasConflictPolicy_ConflictPolicyNotEmpty_ReturnConflict, TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    ErrCode res = policyManager->SetPolicy(testAdminName,
        "conflict_policy", "[{}]", "[{}]", DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));

    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    bool hasConflict = false;
    ErrCode ret = mockPlugin_->HasConflictPolicy(hasConflict, usbDeviceTypes);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(hasConflict);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        "conflict_policy", "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_HasConflictPolicy_NoConflict_ReturnOk
 * @tc.desc: Test HasConflictPolicy when no conflict exists.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_HasConflictPolicy_NoConflict_ReturnOk, TestSize.Level1)
{
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetConflictPolicyName()).WillRepeatedly(Return("conflict_policy"));

    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    bool hasConflict = false;
    ErrCode ret = mockPlugin_->HasConflictPolicy(hasConflict, usbDeviceTypes);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(hasConflict);

    IPolicyManager::policyManagerInstance_ = nullptr;
}

/**
 * @tc.name: DisallowedUsbDevicesPluginBase_CombineDataWithStorageAccessPolicy_UsbStorageDisabled_IncludeStorageType
 * @tc.desc: Test CombineDataWithStorageAccessPolicy when USB storage is disabled.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowedUsbDevicesPluginBaseTest,
    DisallowedUsbDevicesPluginBase_CombineDataWithStorageAccessPolicy_UsbStorageDisabled_IncludeStorageType,
    TestSize.Level1)
{
    const std::string testAdminName = "com.edm.test.demo";
    std::shared_ptr<PolicyManager> policyManager = std::make_shared<PolicyManager>();
    IPolicyManager::policyManagerInstance_ = policyManager.get();

    std::string storagePolicy = std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED);
    ErrCode res = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_USB_READ_ONLY, storagePolicy, storagePolicy, DEFAULT_USER_ID);
    ASSERT_TRUE(res == ERR_OK);

    EXPECT_CALL(*mockPlugin_, GetPluginName()).WillRepeatedly(Return("TestPlugin"));
    EXPECT_CALL(*mockPlugin_, GetSerializer()).WillRepeatedly(Return(serializer_));

    std::vector<USB::UsbDeviceType> policyData;
    std::vector<USB::UsbDeviceType> combineData;
    mockPlugin_->CombineDataWithStorageAccessPolicy(policyData, combineData);
    EXPECT_GE(combineData.size(), 1);

    ErrCode clearRes = policyManager->SetPolicy(testAdminName,
        PolicyName::POLICY_USB_READ_ONLY, "", "", DEFAULT_USER_ID);
    ASSERT_TRUE(clearRes == ERR_OK);
    IPolicyManager::policyManagerInstance_ = nullptr;
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS
