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

#define protected public
#define private public
#include "manage_user_non_stop_apps_plugin_test.h"
#include "manage_user_non_stop_apps_serializer.h"
#include "disallowed_running_bundles_plugin.h"
#undef private
#undef protected

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "array_string_serializer.h"
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
void ManageUserNonStopAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageUserNonStopAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNullData
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnHandlePolicy add when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnHandlePolicyAddFailWithNullData, TestSize.Level1)
{
    ManageUserNonStopAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> userNonStopApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, userNonStopApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNullData
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnHandlePolicy remove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnHandlePolicyRemoveFailWithNullData, TestSize.Level1)
{
    ManageUserNonStopAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> userNonStopApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, userNonStopApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithOversizeData
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnHandlePolicy when data is oversize.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnHandlePolicyFailWithOversizeData, TestSize.Level1)
{
    ManageUserNonStopAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationMsg> userNonStopApps = {
        { "com.example.app1", 100, 0 }, { "com.example.app2", 100, 0 }, { "com.example.app3", 100, 0 },
        { "com.example.app4", 100, 0 }, { "com.example.app5", 100, 0 }, { "com.example.app6", 100, 0 },
        { "com.example.app7", 100, 0 }, { "com.example.app8", 100, 0 }, { "com.example.app9", 100, 0 },
        { "com.example.app10", 100, 0 }, { "com.example.app11", 100, 0 }
    };
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, userNonStopApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicySucceedWithConflictData
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnHandlePolicy when data is conflict.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnHandlePolicySucceedWithConflictData, TestSize.Level1)
{   
    std::string settingsAppIdentifier = "5765880207852919475";
    std::string bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    ASSERT_TRUE(proxy != nullptr);
    ErrCode res = proxy->GetBundleNameByAppId(settingsAppIdentifier, bundleName);
    ASSERT_TRUE(res == ERR_OK);
    std::vector<ApplicationMsg> userNonStopApps = {{ bundleName, 100, 0 }};
    std::vector<ManageUserNonStopAppInfo> currentData;
    std::vector<ManageUserNonStopAppInfo> mergeData;
    ManageUserNonStopAppsPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(userNonStopApps, currentData, mergeData);
    ASSERT_TRUE(ret == ERR_OK);

    ManageUserNonStopAppsPlugin userNonStopPlugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, userNonStopApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
    ret = userNonStopPlugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    mergeData.clear();
    ret = plugin.OnRemovePolicy(userNonStopApps, currentData, mergeData);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyWithNotExistedData
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnHandlePolicy remove when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnHandlePolicyFailWithNotExistedData, TestSize.Level1)
{
    std::vector<ApplicationMsg> userNonStopApps1 = { {"com.not.existed", 100, 0} };
    ManageUserNonStopAppsPlugin plugin;

    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, userNonStopApps1);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS);
    ErrCode res = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(res == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFail
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnGetPolicyFail, TestSize.Level1)
{
    ManageUserNonStopAppsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<ApplicationMsg> userNonStopApps = {{ "com.example.app", 100, 0 }};
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, userNonStopApps);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ApplicationInstanceHandle::ReadApplicationInstanceVector(reply, userNonStopApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (userNonStopApps.empty()));
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ManageUserNonStopAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageUserNonStopAppsPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    ManageUserNonStopAppsPlugin plugin;
    std::string adminName;
    std::string currentJsonData;
    std::string mergeJsonData;
    plugin.OnAdminRemove(adminName, currentJsonData, mergeJsonData, DEFAULT_USER_ID);

    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("bundleName");
    std::vector<ApplicationMsg> userNonStopApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, userNonStopApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (userNonStopApps.empty()));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
