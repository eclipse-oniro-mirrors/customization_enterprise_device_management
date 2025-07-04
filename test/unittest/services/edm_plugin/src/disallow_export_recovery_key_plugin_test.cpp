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

#include <gtest/gtest.h>
#include "disallow_export_recovery_key_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_BUNDLE_NAME = "testBundleName";
class DisallowExportRecoveryKeyPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);

    static void TearDownTestSuite(void);
};

void DisallowExportRecoveryKeyPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowExportRecoveryKeyPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: DisallowExportRecoveryKeyOnSetPolicy
 * @tc.desc: Test DisallowExportRecoveryKeyPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowExportRecoveryKeyPluginTest, DisallowExportRecoveryKeyOnSetPolicy, TestSize.Level1)
{
    DisallowExportRecoveryKeyPlugin plugin;
    bool data = true;
    bool currentData;
    bool mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = false;
    ret = plugin.OnSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: DisallowExportRecoveryKeyAdminRemove
 * @tc.desc: Test DisallowExportRecoveryKeyPlugin::OnAdminRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowExportRecoveryKeyPluginTest, DisallowExportRecoveryKeyAdminRemove, TestSize.Level1)
{
    DisallowExportRecoveryKeyPlugin plugin;
    bool data = false;
    bool mergeData = true;
    ErrCode ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    data = true;
    mergeData = false;
    ret = plugin.OnAdminRemove(TEST_BUNDLE_NAME, data, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS