/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "manage_keep_alive_apps_plugin_test.h"

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"

#include "disallowed_running_bundles_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "func_code.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ManageKeepAliveAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageKeepAliveAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNullData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy add when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyAddFailWithNullData, TestSize.Level1)
{
    ManageKeepAliveAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<std::string> keepAliveApps;
    data.WriteStringVector(keepAliveApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNullData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy remove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyRemoveFailWithNullData, TestSize.Level1)
{
    ManageKeepAliveAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<std::string> keepAliveApps;
    data.WriteStringVector(keepAliveApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithOversizeData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy when data is oversize.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyFailWithOversizeData, TestSize.Level1)
{
    ManageKeepAliveAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<std::string> keepAliveApps =
        {"com.test1", "com.test2", "com.test3", "com.test4", "com.test5", "com.test6"};
    data.WriteStringVector(keepAliveApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithConflictData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy when data is conflict.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyFailWithConflictData, TestSize.Level1)
{
    std::vector<std::string> keepAliveApps = {"com.test"};
    std::vector<std::string> currentData;
    DisallowedRunningBundlesPlugin disllowedPlugin;
    disllowedPlugin.OnSetPolicy(keepAliveApps, currentData, DEFAULT_USER_ID);

    ManageKeepAliveAppsPlugin keepAlivePlugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    data.WriteStringVector(keepAliveApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = keepAlivePlugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    disllowedPlugin.OnRemovePolicy(keepAliveApps, currentData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED);
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNotExistedData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy add when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyAddFailWithNotExistedData, TestSize.Level1)
{
    std::vector<std::string> keepAliveApps = {"com.not.existed"};
    ManageKeepAliveAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    data.WriteStringVector(keepAliveApps);
    HandlePolicyData policyData;

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNotExistedData
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnHandlePolicy remove when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnHandlePolicyRemoveFailWithNotExistedData, TestSize.Level1)
{
    std::vector<std::string> keepAliveApps = {"com.not.existed"};
    ManageKeepAliveAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    data.WriteStringVector(keepAliveApps);
    HandlePolicyData policyData;

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(reply.ReadInt32() == EdmReturnErrCode::ADD_KEEP_ALIVE_APP_FAILED);
    ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnGetPolicyFail
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnGetPolicyFail, TestSize.Level1)
{
    ManageKeepAliveAppsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> keepAliveApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    reply.ReadStringVector(&keepAliveApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (keepAliveApps.empty()));
}

/**
 * @tc.name: TestOnAdminRemoveDoneFail
 * @tc.desc: Test ManageKeepAliveAppsPlugin::OnAdminRemoveDone.
 * @tc.type: FUNC
 */
HWTEST_F(ManageKeepAliveAppsPluginTest, TestOnAdminRemoveDoneFail, TestSize.Level1)
{
    ManageKeepAliveAppsPlugin plugin;
    std::string adminName;
    std::string currentJsonData;
    plugin.OnAdminRemoveDone(adminName, currentJsonData, DEFAULT_USER_ID);

    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> keepAliveApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    reply.ReadStringVector(&keepAliveApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (keepAliveApps.empty()));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS