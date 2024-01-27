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

#include "manage_auto_start_apps_plugin_test.h"

#include <bundle_info.h>
#include <bundle_mgr_interface.h>

#include "edm_log.h"
#include "edm_constants.h"
#include "edm_sys_manager.h"
#include "if_system_ability_manager.h"
#include "install_plugin.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uninstall_plugin.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string RIGHT_TEST_BUNDLE = "com.example.l3jsdemo/com.example.l3jsdemo.MainAbility";
const std::string ERROR_TEST_BUNDLE = "com.example.l3jsdemo/com.example.l3jsdemo.ErrorAbility";
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";

void ManageAutoStartAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageAutoStartAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin001, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when budle is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin002, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::vector<std::string> data = {RIGHT_TEST_BUNDLE};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when budle is existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin003, TestSize.Level1)
{
    InstallPlugin installPlugin;
    InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
    MessageParcel reply;
    ErrCode ret = installPlugin.OnSetPolicy(param, reply);
    ASSERT_TRUE(ret == ERR_OK);

    ManageAutoStartAppsPlugin plugin;
    std::vector<std::string> data = {RIGHT_TEST_BUNDLE};
    std::vector<std::string> currentData;
    ret = plugin.OnSetPolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    std::string policyData = RIGHT_TEST_BUNDLE;
    MessageParcel parcel;
    MessageParcel getReply;
    ret = plugin.OnGetPolicy(policyData, parcel, getReply, DEFAULT_USER_ID);
    std::vector<std::string> res;
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(getReply.ReadInt32() == ERR_OK);
    getReply.ReadStringVector(&res);
    ASSERT_TRUE(res.size() >= 1);
    ASSERT_TRUE(std::find(res.begin(), res.end(), RIGHT_TEST_BUNDLE) != res.end());

    ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);

    MessageParcel removeReply;
    ret = plugin.OnGetPolicy(policyData, parcel, removeReply, DEFAULT_USER_ID);
    std::vector<std::string> afterRemove;
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(removeReply.ReadInt32() == ERR_OK);
    removeReply.ReadStringVector(&afterRemove);
    ASSERT_TRUE(afterRemove.size() == 0);

    UninstallPlugin uninstallPlugin;
    UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
    MessageParcel uninstallReply;
    ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin004, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::string policyData = RIGHT_TEST_BUNDLE;
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin005, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::vector<std::string> data;
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestManageAutoStartAppsPlugin
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnRemovePolicy when budle is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestManageAutoStartAppsPlugin006, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::vector<std::string> data = {ERROR_TEST_BUNDLE};
    std::vector<std::string> currentData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS