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
} // namespace TEST
} // namespace EDM
} // namespace OHOS