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

#include "set_domain_account_policy_plugin.h"

#include <gtest/gtest.h>

#include "domain_account_common.h"
#include "domain_account_policy.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetDomainAccountPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetDomainAccountPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetDomainAccountPolicyPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyFuncCodeError
 * @tc.desc: Test OnHandlePolicy error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnHandlePolicyFuncCodeError, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE,
        EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyParamTypeError
 * @tc.desc: Test OnHandlePolicy param type error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnHandlePolicyParamTypeError, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    data.WriteBool(false); // correct value should is DomainPolicyInfo
    DomainAccountPolicy domainAccountPolicy(300, 200, 100);
    domainAccountPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);

    MessageParcel data2;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo;
    domainAccountInfo.Marshalling(data2);
    MessageParcel reply2;
    ret = plugin->OnHandlePolicy(funcCode, data2, reply2, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyDomainAccountPolicyCheckParameterValidityError
 * @tc.desc: Test OnHandlePolicy DomainAccountPolicy CheckParameterValidity error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnHandlePolicyDomainAccountPolicyCheckParameterValidityError,
    TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo;
    domainAccountInfo.Marshalling(data);
    DomainAccountPolicy domainAccountPolicy(300, -2, 100); // -2 is error param
    domainAccountPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyDomainAccountInfoError
 * @tc.desc: Test OnHandlePolicy DomainAccountInfo error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnHandlePolicyDomainAccountInfoError, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo;
    std::string errValue = "errValue";
    domainAccountInfo.accountId_ = errValue;
    domainAccountInfo.accountName_ = errValue;
    domainAccountInfo.domain_ = errValue;
    domainAccountInfo.serverConfigId_ = errValue;
    domainAccountInfo.Marshalling(data);
    DomainAccountPolicy domainAccountPolicy(300, 200, 100);
    domainAccountPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicyParamTypeError
 * @tc.desc: Test OnGetPolicy param type error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnGetPolicyParamTypeError, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    data.WriteBool(false);
    MessageParcel reply;
    std::string policyData{"TestString"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicyDomainAccountInfoError
 * @tc.desc: Test OnGetPolicy DomainAccountInfo error
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnGetPolicyDomainAccountInfoError, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo;
    std::string errValue = "errValue";
    domainAccountInfo.accountId_ = errValue;
    domainAccountInfo.accountName_ = errValue;
    domainAccountInfo.domain_ = errValue;
    domainAccountInfo.serverConfigId_ = errValue;
    domainAccountInfo.Marshalling(data);
    MessageParcel reply;
    std::string policyData{"TestString"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyAndOnGetPolicyNormal
 * @tc.desc: Test OnHandlePolicy And OnGetPolicy normal
 * @tc.type: FUNC
 */
HWTEST_F(SetDomainAccountPolicyPluginTest, TestOnHandlePolicyAndOnGetPolicyNormal, TestSize.Level1)
{
    std::shared_ptr<SetDomainAccountPolicyPlugin> plugin = std::make_shared<SetDomainAccountPolicyPlugin>();
    MessageParcel data;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo;
    domainAccountInfo.Marshalling(data);
    DomainAccountPolicy domainAccountPolicy(300, 200, 100);
    domainAccountPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", "", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET,
        EdmInterfaceCode::DOMAIN_ACCOUNT_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    MessageParcel dataOnGetPolicy;
    OHOS::AccountSA::DomainAccountInfo domainAccountInfo2;
    domainAccountInfo2.Marshalling(dataOnGetPolicy);
    MessageParcel replyOnGetPolicy;
    std::string policyData{"TestString"};
    ret = plugin->OnGetPolicy(policyData, dataOnGetPolicy, replyOnGetPolicy, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(replyCode == ERR_OK);

    DomainAccountPolicy domainAccountPolicy2;
    bool unmar = DomainAccountPolicy::Unmarshalling(replyOnGetPolicy, domainAccountPolicy2);
    ASSERT_TRUE(unmar);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS