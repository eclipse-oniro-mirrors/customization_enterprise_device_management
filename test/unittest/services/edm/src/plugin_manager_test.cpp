/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "plugin_manager_test.h"
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include "func_code_utils.h"
#include "plugin_manager.h"
#include "string_ex.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
void PluginManagerTest::SetUp()
{
    PluginManager::GetInstance()->AddPlugin(std::make_shared<TestPlugin>());
}

void PluginManagerTest::TearDown()
{
    PluginManager::GetInstance().reset();
}

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test PluginManager GetInstance func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetInstance, TestSize.Level1)
{
    ASSERT_TRUE(PluginManager::GetInstance() != nullptr);
    ASSERT_TRUE(PluginManager::GetInstance().get() != nullptr);
}

/**
 * @tc.name: TestGetPluginByFuncCode
 * @tc.desc: Test PluginManager GetPluginByFuncCode func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginByFuncCode, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByFuncCode(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 0));
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetPolicyName() == "TestPlugin");
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByFuncCode(
        POLICY_FUNC_CODE((uint32_t)FuncOperateType::SET, 100000)) == nullptr);
}

/**
 * @tc.name: TestGetPluginByPolicyName
 * @tc.desc: Test PluginManager GetPluginByPolicyName func.
 * @tc.type: FUNC
 */
HWTEST_F(PluginManagerTest, TestGetPluginByPolicyName, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = PluginManager::GetInstance()->GetPluginByPolicyName("TestPlugin");
    ASSERT_TRUE(plugin != nullptr);
    ASSERT_TRUE(plugin->GetCode() == 0);
    ASSERT_TRUE(PluginManager::GetInstance()->GetPluginByPolicyName("XXXXExamplePlugin") == nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
