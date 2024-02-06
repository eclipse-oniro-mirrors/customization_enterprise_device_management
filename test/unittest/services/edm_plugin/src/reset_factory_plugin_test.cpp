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

#include "reset_factory_plugin_test.h"
#include "edm_ipc_interface_code.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DeviceControlPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DeviceControlPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestRestFactory
 * @tc.desc: Test RestFactoryPlugin::OnSetPolicy function fail.
 * @tc.type: FUNC
 */
HWTEST_F(DeviceControlPluginTest, TestRestFactory, TestSize.Level1)
{
    Utils::ResetTokenTypeAndUid();
    std::shared_ptr<IPlugin> plugin = ResetFactoryPlugin::GetPlugin();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::RESET_FACTORY);
    HandlePolicyData handlePolicyData;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS