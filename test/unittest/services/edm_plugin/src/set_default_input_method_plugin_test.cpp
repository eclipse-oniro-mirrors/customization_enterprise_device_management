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

#include "set_default_input_method_plugin.h"

#include <gtest/gtest.h>

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

class SetDefaultInputMethodPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void SetDefaultInputMethodPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetDefaultInputMethodPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicy_001
 * @tc.desc: Test OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetDefaultInputMethodPluginTest, TestOnSetPolicy_001, TestSize.Level1)
{
    SetDefaultInputMethodPlugin plugin;
    std::string data = "112233";
    ErrCode code = plugin.OnSetPolicy(data);
    ASSERT_EQ(code, EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS