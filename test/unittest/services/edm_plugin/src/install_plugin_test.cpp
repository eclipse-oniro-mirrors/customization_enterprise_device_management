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

#include "install_plugin_test.h"

#include "uninstall_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";

void InstallPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void InstallPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test InstallPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(InstallPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    InstallPlugin plugin;
    InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
    MessageParcel reply;
    ErrCode ret = plugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);
    UninstallPlugin uninstallPlugin;
    UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
    MessageParcel uninstallReply;
    ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS