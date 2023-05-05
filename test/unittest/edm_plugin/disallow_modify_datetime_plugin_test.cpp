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

#include "disallow_modify_datetime_plugin_test.h"
#include "disallow_modify_datetime_plugin.h"
#include "iplugin.h"
#include "policy_info.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowModifyDateTimePluginTest::SetUpTestCase(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowModifyDateTimePluginTest::TearDownTestCase(void)
{
    Utils::ResetTokenTypeAndUid();
}

/**
 * @tc.name: TestDisallowModifyDateTimePlugin
 * @tc.desc: Test TestDisallowModifyDateTimePlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowModifyDateTimePluginTest, TestDisallowModifyDateTimePlugin001, TestSize.Level1)
{
    MessageParcel data;
    // want to disallow to modify date time.
    data.WriteBool(true);
    std::shared_ptr<IPlugin> plugin = DisallModifyDateTimePlugin::GetPlugin();
    // origin policy is allow to modify date time.
    std::string policyData{"false"};
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, DISALLOW_MODIFY_DATETIME);
    bool isChanged = false;
    ErrCode ret = plugin->OnHandlePolicy(funcCode, data, policyData, isChanged, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    // current policy is disallow to modify date time.
    ASSERT_TRUE(policyData == "true");
    ASSERT_TRUE(isChanged);
}

/**
 * @tc.name: TestDisallowModifyDateTimePlugin
 * @tc.desc: Test TestDisallowModifyDateTimePlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowModifyDateTimePluginTest, TestDisallowModifyDateTimePlugin002, TestSize.Level1)
{
    std::shared_ptr<IPlugin> plugin = DisallModifyDateTimePlugin::GetPlugin();
    // origin policy is disallow to modify date time.
    std::string policyData{"true"};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    int32_t flag = ERR_INVALID_VALUE;
    ASSERT_TRUE(reply.ReadInt32(flag) && (flag == ERR_OK));
    bool result = false;
    reply.ReadBool(result);
    ASSERT_TRUE(ret == ERR_OK);
    // get policy is disallow to modify date time.
    ASSERT_TRUE(result);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS