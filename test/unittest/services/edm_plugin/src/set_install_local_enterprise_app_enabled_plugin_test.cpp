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

#include "set_install_local_enterprise_app_enabled_plugin_test.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#define protected public
#define private public
#include "basic_bool_plugin.h"
#include "install_local_enterprise_app_enabled_plugin.h"
#undef private
#undef protected
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string PERSIST_EDM_SET_LOCAL_APP_INSTALL_MODE = "persist.edm.is_local_install_enable";
void SetInstallLocalEnterpriseAppEnabledPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void SetInstallLocalEnterpriseAppEnabledPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    OHOS::system::SetParameter(PERSIST_EDM_SET_LOCAL_APP_INSTALL_MODE, "false");
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test InstallLocalEnterpriseAppEnabledPlugin::OnGetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetInstallLocalEnterpriseAppEnabledPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    int32_t userId = 0;
    InstallLocalEnterpriseAppEnabledPlugin plugin;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, userId);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    ASSERT_FALSE(reply.ReadBool());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
