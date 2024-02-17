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

#include "power_policy_plugin.h"

#include <gtest/gtest.h>

#include "edm_data_ability_utils_mock.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class PowerPolicyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void PowerPolicyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void PowerPolicyPluginTest::TearDownTestSuite(void)
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
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyFuncCodeError, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::POWER_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyPowerPolicyUnmarshallingError
 * @tc.desc: Test OnHandlePolicy PowerPolicy Unmarshalling error
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyPowerPolicyUnmarshallingError, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    data.WriteUint32(1000); // error action
    data.WriteUint32(1000);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyPowerSceneError
 * @tc.desc: Test OnHandlePolicy Power scene error
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyPowerSceneError, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(1000); // error number
    PowerPolicy powerPolicy;
    powerPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyNormal
 * @tc.desc: Test OnHandlePolicy normal
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyNormal, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    PowerPolicy powerPolicy;
    powerPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    EdmDataAbilityUtils::SetResult("power_suspend_normal");
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyJsonReaderError
 * @tc.desc: Test OnHandlePolicy json reader error
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyJsonReaderError, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    PowerPolicy powerPolicy;
    powerPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    EdmDataAbilityUtils::SetResult("power_suspend_json_error");
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyJsonNoPowerSceneKey
 * @tc.desc: Test OnHandlePolicy json no power scene key
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyJsonNoPowerSceneKey, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    PowerPolicy powerPolicy;
    powerPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    EdmDataAbilityUtils::SetResult("power_suspend_json_no_time_out");
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyPowerSceneKeyNotObject
 * @tc.desc: Test OnHandlePolicy power scene not object
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnHandlePolicyPowerSceneKeyNotObject, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    PowerPolicy powerPolicy;
    powerPolicy.Marshalling(data);
    MessageParcel reply;
    HandlePolicyData handlePolicyData{"TestString", false};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::POWER_POLICY);
    EdmDataAbilityUtils::SetResult("power_suspend_json_key_not_object");
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicyPowerSceneError
 * @tc.desc: Test OnGetPolicy power scene error
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnGetPolicyPowerSceneError, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(1000); // error param
    MessageParcel reply;
    std::string policyData{"TestString"};
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnGetPolicyNormal
 * @tc.desc: Test OnGetPolicy normal
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnGetPolicyNormal, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    MessageParcel reply;
    std::string policyData{"TestString"};
    EdmDataAbilityUtils::SetResult("power_suspend_normal");
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(replyCode == ERR_OK);
    PowerPolicy powerPolicy;
    bool unmar = PowerPolicy::Unmarshalling(reply, powerPolicy);
    ASSERT_TRUE(unmar);
}

/**
 * @tc.name: TestOnGetPolicyPowerSceneKeyNotObject
 * @tc.desc: Test OnGetPolicy power scene key not object
 * @tc.type: FUNC
 */
HWTEST_F(PowerPolicyPluginTest, TestOnGetPolicyPowerSceneKeyNotObject, TestSize.Level1)
{
    std::shared_ptr<PowerPolicyPlugin> plugin = std::make_shared<PowerPolicyPlugin>();
    MessageParcel data;
    data.WriteUint32(static_cast<uint32_t>(PowerScene::TIME_OUT));
    MessageParcel reply;
    std::string policyData{"TestString"};
    EdmDataAbilityUtils::SetResult("power_suspend_json_key_not_object");
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t replyCode = reply.ReadInt32();
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(replyCode == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS