/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "user_cert_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
static const uint8_t CERT_DATA[] = {/* 40dc992e.0 */
    0x30, 0x82, 0x04, 0x31, 0x30, 0x82, 0x03, 0x19, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x52, 0x31, 0x44, 0x30, 0x42, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
    0x3b, 0x48, 0x65, 0x6c, 0x6c, 0x65, 0x6e, 0x69, 0x63, 0x20, 0x41, 0x63, 0x61, 0x64, 0x65, 0x6d, 0x69, 0x63, 0x20,
    0x61, 0x6e, 0x64, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74,
    0x75, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x43, 0x65, 0x72, 0x74, 0x2e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
    0x69, 0x74, 0x79, 0x31, 0x40, 0x30, 0x3e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x37, 0x48, 0x65, 0x6c, 0x6c, 0x65,
    0x6e, 0x69, 0x63, 0x20, 0x41, 0x63, 0x61, 0x64, 0x65, 0x6d, 0x69, 0x63, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x52, 0x65,
    0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x73,
    0x20, 0x52, 0x6f, 0x6f, 0x74, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x31, 0x31,
    0x32, 0x30, 0x36, 0x31, 0x33, 0x34, 0x39, 0x35, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x31, 0x31, 0x32, 0x30, 0x31, 0x31,
    0x33, 0x34, 0x39, 0x35, 0x32, 0x5a, 0x30, 0x81, 0x95, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x47, 0x52, 0x31, 0x44, 0x30, 0x42, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x3b, 0x48, 0x65, 0x6c, 0x6c, 0x65,
    0x6e, 0x69, 0x63, 0x20, 0x41, 0x63, 0x61, 0x64, 0x65, 0x6d, 0x69, 0x63, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x52, 0x65,
    0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x73,
    0x20, 0x43, 0x65, 0x72, 0x74, 0x2e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x40, 0x30,
    0x3e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x37, 0x48, 0x65, 0x6c, 0x6c, 0x65, 0x6e, 0x69, 0x63, 0x20, 0x41, 0x63,
    0x61, 0x64, 0x65, 0x6d, 0x69, 0x63, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
    0x20, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x43,
    0x41, 0x20, 0x32, 0x30, 0x31, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xa9, 0x53, 0x00, 0xe3, 0x2e, 0xa6, 0xf6, 0x8e, 0xfa, 0x60, 0xd8, 0x2d, 0x95, 0x3e, 0xf8, 0x2c, 0x2a, 0x54,
    0x4e, 0xcd, 0xb9, 0x84, 0x61, 0x94, 0x58, 0x4f, 0x8f, 0x3d, 0x8b, 0xe4, 0x43, 0xf3, 0x75, 0x89, 0x8d, 0x51, 0xe4,
    0xc3, 0x37, 0xd2, 0x8a, 0x88, 0x4d, 0x79, 0x1e, 0xb7, 0x12, 0xdd, 0x43, 0x78, 0x4a, 0x8a, 0x92, 0xe6, 0xd7, 0x48,
    0xd5, 0x0f, 0xa4, 0x3a, 0x29, 0x44, 0x35, 0xb8, 0x07, 0xf6, 0x68, 0x1d, 0x55, 0xcd, 0x38, 0x51, 0xf0, 0x8c, 0x24,
    0x31, 0x85, 0xaf, 0x83, 0xc9, 0x7d, 0xe9, 0x77, 0xaf, 0xed, 0x1a, 0x7b, 0x9d, 0x17, 0xf9, 0xb3, 0x9d, 0x38, 0x50,
    0x0f, 0xa6, 0x5a, 0x79, 0x91, 0x80, 0xaf, 0x37, 0xae, 0xa6, 0xd3, 0x31, 0xfb, 0xb5, 0x26, 0x09, 0x9d, 0x3c, 0x5a,
    0xef, 0x51, 0xc5, 0x2b, 0xdf, 0x96, 0x5d, 0xeb, 0x32, 0x1e, 0x02, 0xda, 0x70, 0x49, 0xec, 0x6e, 0x0c, 0xc8, 0x9a,
    0x37, 0x8d, 0xf7, 0xf1, 0x36, 0x60, 0x4b, 0x26, 0x2c, 0x82, 0x9e, 0xd0, 0x78, 0xf3, 0x0d, 0x0f, 0x63, 0xa4, 0x51,
    0x30, 0xe1, 0xf9, 0x2b, 0x27, 0x12, 0x07, 0xd8, 0xea, 0xbd, 0x18, 0x62, 0x98, 0xb0, 0x59, 0x37, 0x7d, 0xbe, 0xee,
    0xf3, 0x20, 0x51, 0x42, 0x5a, 0x83, 0xef, 0x93, 0xba, 0x69, 0x15, 0xf1, 0x62, 0x9d, 0x9f, 0x99, 0x39, 0x82, 0xa1,
    0xb7, 0x74, 0x2e, 0x8b, 0xd4, 0xc5, 0x0b, 0x7b, 0x2f, 0xf0, 0xc8, 0x0a, 0xda, 0x3d, 0x79, 0x0a, 0x9a, 0x93, 0x1c,
    0xa5, 0x28, 0x72, 0x73, 0x91, 0x43, 0x9a, 0xa7, 0xd1, 0x4d, 0x85, 0x84, 0xb9, 0xa9, 0x74, 0x8f, 0x14, 0x40, 0xc7,
    0xdc, 0xde, 0xac, 0x41, 0x64, 0x6c, 0xb4, 0x19, 0x9b, 0x02, 0x63, 0x6d, 0x24, 0x64, 0x8f, 0x44, 0xb2, 0x25, 0xea,
    0xce, 0x5d, 0x74, 0x0c, 0x63, 0x32, 0x5c, 0x8d, 0x87, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81, 0x89, 0x30,
    0x81, 0x86, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0xa6, 0x91, 0x42, 0xfd, 0x13, 0x61, 0x4a, 0x23, 0x9e, 0x08, 0xa4, 0x29, 0xe5, 0xd8,
    0x13, 0x04, 0x23, 0xee, 0x41, 0x25, 0x30, 0x47, 0x06, 0x03, 0x55, 0x1d, 0x1e, 0x04, 0x40, 0x30, 0x3e, 0xa0, 0x3c,
    0x30, 0x05, 0x82, 0x03, 0x2e, 0x67, 0x72, 0x30, 0x05, 0x82, 0x03, 0x2e, 0x65, 0x75, 0x30, 0x06, 0x82, 0x04, 0x2e,
    0x65, 0x64, 0x75, 0x30, 0x06, 0x82, 0x04, 0x2e, 0x6f, 0x72, 0x67, 0x30, 0x05, 0x81, 0x03, 0x2e, 0x67, 0x72, 0x30,
    0x05, 0x81, 0x03, 0x2e, 0x65, 0x75, 0x30, 0x06, 0x81, 0x04, 0x2e, 0x65, 0x64, 0x75, 0x30, 0x06, 0x81, 0x04, 0x2e,
    0x6f, 0x72, 0x67, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x01, 0x00, 0x1f, 0xef, 0x79, 0x41, 0xe1, 0x7b, 0x6e, 0x3f, 0xb2, 0x8c, 0x86, 0x37, 0x42, 0x4a, 0x4e,
    0x1c, 0x37, 0x1e, 0x8d, 0x66, 0xba, 0x24, 0x81, 0xc9, 0x4f, 0x12, 0x0f, 0x21, 0xc0, 0x03, 0x97, 0x86, 0x25, 0x6d,
    0x5d, 0xd3, 0x22, 0x29, 0xa8, 0x6c, 0xa2, 0x0d, 0xa9, 0xeb, 0x3d, 0x06, 0x5b, 0x99, 0x3a, 0xc7, 0xcc, 0xc3, 0x9a,
    0x34, 0x7f, 0xab, 0x0e, 0xc8, 0x4e, 0x1c, 0xe1, 0xfa, 0xe4, 0xdc, 0xcd, 0x0d, 0xbe, 0xbf, 0x24, 0xfe, 0x6c, 0xe7,
    0x6b, 0xc2, 0x0d, 0xc8, 0x06, 0x9e, 0x4e, 0x8d, 0x61, 0x28, 0xa6, 0x6a, 0xfd, 0xe5, 0xf6, 0x62, 0xea, 0x18, 0x3c,
    0x4e, 0xa0, 0x53, 0x9d, 0xb2, 0x3a, 0x9c, 0xeb, 0xa5, 0x9c, 0x91, 0x16, 0xb6, 0x4d, 0x82, 0xe0, 0x0c, 0x05, 0x48,
    0xa9, 0x6c, 0xf5, 0xcc, 0xf8, 0xcb, 0x9d, 0x49, 0xb4, 0xf0, 0x02, 0xa5, 0xfd, 0x70, 0x03, 0xed, 0x8a, 0x21, 0xa5,
    0xae, 0x13, 0x86, 0x49, 0xc3, 0x33, 0x73, 0xbe, 0x87, 0x3b, 0x74, 0x8b, 0x17, 0x45, 0x26, 0x4c, 0x16, 0x91, 0x83,
    0xfe, 0x67, 0x7d, 0xcd, 0x4d, 0x63, 0x67, 0xfa, 0xf3, 0x03, 0x12, 0x96, 0x78, 0x06, 0x8d, 0xb1, 0x67, 0xed, 0x8e,
    0x3f, 0xbe, 0x9f, 0x4f, 0x02, 0xf5, 0xb3, 0x09, 0x2f, 0xf3, 0x4c, 0x87, 0xdf, 0x2a, 0xcb, 0x95, 0x7c, 0x01, 0xcc,
    0xac, 0x36, 0x7a, 0xbf, 0xa2, 0x73, 0x7a, 0xf7, 0x8f, 0xc1, 0xb5, 0x9a, 0xa1, 0x14, 0xb2, 0x8f, 0x33, 0x9f, 0x0d,
    0xef, 0x22, 0xdc, 0x66, 0x7b, 0x84, 0xbd, 0x45, 0x17, 0x06, 0x3d, 0x3c, 0xca, 0xb9, 0x77, 0x34, 0x8f, 0xca, 0xea,
    0xcf, 0x3f, 0x31, 0x3e, 0xe3, 0x88, 0xe3, 0x80, 0x49, 0x25, 0xc8, 0x97, 0xb5, 0x9d, 0x9a, 0x99, 0x4d, 0xb0, 0x3c,
    0xf8, 0x4a, 0x00, 0x9b, 0x64, 0xdd, 0x9f, 0x39, 0x4b, 0xd1, 0x27, 0xd7, 0xb8};

class UserCertPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void UserCertPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void UserCertPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyGet
 * @tc.desc: Test UserCertPlugin::OnSetPolicy get case
 * @tc.type: FUNC
 */
HWTEST_F(UserCertPluginTest, TestOnHandlePolicyGet, TestSize.Level1)
{
    std::shared_ptr<UserCertPlugin> plugin = std::make_shared<UserCertPlugin>();
    MessageParcel data;
    MessageParcel reply;
    std::string policyData{"TestString"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::INSTALL_CERTIFICATE);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyInstall
 * @tc.desc: Test UserCertPlugin::OnHandlePolicy install
 * @tc.type: FUNC
 */
HWTEST_F(UserCertPluginTest, TestOnHandlePolicyInstall, TestSize.Level1)
{
    std::shared_ptr<UserCertPlugin> plugin = std::make_shared<UserCertPlugin>();
    std::vector<uint8_t> certArray;
    certArray.push_back(0x30);
    std::string alias = "edm_alias_test";
    MessageParcel data;
    data.WriteUInt8Vector(certArray);
    data.WriteString(alias);
    MessageParcel reply;
    std::string policyData{"TestString"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_CERTIFICATE);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t replyCode = ERR_INVALID_VALUE;
    reply.ReadInt32(replyCode);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyUninstall
 * @tc.desc: Test UserCertPlugin::OnHandlePolicy uninstall
 * @tc.type: FUNC
 */
HWTEST_F(UserCertPluginTest, TestOnHandlePolicyUninstall, TestSize.Level1)
{
    std::shared_ptr<UserCertPlugin> plugin = std::make_shared<UserCertPlugin>();
    std::string alias = "edm_alias_test";
    MessageParcel data;
    data.WriteString(alias);
    MessageParcel reply;
    std::string policyData{"TestString"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::INSTALL_CERTIFICATE);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t replyCode = ERR_INVALID_VALUE;
    reply.ReadInt32(replyCode);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::MANAGED_CERTIFICATE_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyInstallSuccess
 * @tc.desc: Test UserCertPlugin::OnHandlePolicy install
 * @tc.type: FUNC
 */
HWTEST_F(UserCertPluginTest, TestOnHandlePolicyInstallSuccess, TestSize.Level1)
{
    std::shared_ptr<UserCertPlugin> plugin = std::make_shared<UserCertPlugin>();
    std::string alias = "edm_alias_cert";
    std::vector<uint8_t> certArray(CERT_DATA, CERT_DATA + sizeof(CERT_DATA) / sizeof(CERT_DATA[0]));
    MessageParcel data;
    data.WriteUInt8Vector(certArray);
    data.WriteString(alias);
    MessageParcel reply;
    std::string policyData{"TestString"};
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::INSTALL_CERTIFICATE);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    int32_t replyCode = ERR_INVALID_VALUE;
    reply.ReadInt32(replyCode);
    ASSERT_TRUE(replyCode == ERR_OK);
    std::string result = reply.ReadString();

    funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::INSTALL_CERTIFICATE);
    MessageParcel dataUninstall;
    dataUninstall.WriteString(result);
    MessageParcel replyUninstall;
    ret = plugin->OnHandlePolicy(funcCode, dataUninstall, replyUninstall, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    replyCode = ERR_INVALID_VALUE;
    replyUninstall.ReadInt32(replyCode);
    ASSERT_TRUE(replyCode == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS