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
#include "manage_freeze_exempted_apps_plugin_test.h"
#include "manage_freeze_exempted_apps_serializer.h"
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
#include "edm_bundle_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ManageFreezeExemptedAppsPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ManageFreezeExemptedAppsPluginTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNullData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy add when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyAddFailWithNullData, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> freezeExemptedApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNullData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy remove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyRemoveFailWithNullData, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationInstance> freezeExemptedApps;
    ApplicationInstanceHandle::WriteApplicationInstanceVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithOversizeData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy when data is oversize.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyFailWithOversizeData, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<ApplicationMsg> freezeExemptedApps = {
        { "com.example.app1", 100, 0 }, { "com.example.app2", 100, 0 }, { "com.example.app3", 100, 0 },
        { "com.example.app4", 100, 0 }, { "com.example.app5", 100, 0 }, { "com.example.app6", 100, 0 },
        { "com.example.app7", 100, 0 }, { "com.example.app8", 100, 0 }, { "com.example.app9", 100, 0 },
        { "com.example.app10", 100, 0 }, { "com.example.app11", 100, 0 }
    };
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithConflictData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy when data is conflict.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicySucceedWithConflictData, TestSize.Level1)
{
    std::string cameraAppIdentifier = "5765880207854258995";
    std::string bundleName;
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    ASSERT_TRUE(proxy != nullptr);
    ErrCode res = proxy->GetBundleNameByAppId(cameraAppIdentifier, bundleName);
    ASSERT_TRUE(res == ERR_OK);
    std::vector<ApplicationMsg> freezeExemptedApps = {{ bundleName, 100, 0 }};
    std::vector<ManageFreezeExemptedAppInfo> currentData;
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    ManageFreezeExemptedAppsPlugin plugin;
    ErrCode ret = plugin.OnSetPolicy(freezeExemptedApps, currentData, mergeData);
    ASSERT_TRUE(ret == ERR_OK);

    ManageFreezeExemptedAppsPlugin freezeExemptedPlugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, freezeExemptedApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ret = freezeExemptedPlugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    mergeData.clear();
    ret = plugin.OnRemovePolicy(freezeExemptedApps, currentData, mergeData);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNotExistedData
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnHandlePolicy remove when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnHandlePolicyRemoveFailWithNotExistedData, TestSize.Level1)
{
    std::vector<ApplicationMsg> freezeExemptedApps1 = { {"com.existed.app", 100, 0} };
    std::vector<ApplicationMsg> freezeExemptedApps2 = { {"com.not.existed", 100, 0} };
    std::vector<ManageFreezeExemptedAppInfo> currentData;
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    ManageFreezeExemptedAppsPlugin plugin;

    MessageParcel data;
    MessageParcel reply;
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, freezeExemptedApps2);
    HandlePolicyData policyData;
    std::vector<ManageFreezeExemptedAppInfo> freezeExemptedData;
    std::string freezeExemptedStr = plugin.SerializeApplicationInstanceVectorToJson(freezeExemptedApps1);
    ManageFreezeExemptedAppsSerializer::GetInstance()->Deserialize(freezeExemptedStr, freezeExemptedData);
    ManageFreezeExemptedAppsSerializer::GetInstance()->Serialize(freezeExemptedData, policyData.policyData);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
}

/**
 * @tc.name: TestOnGetPolicyFail
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnGetPolicyFail, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<ApplicationMsg> freezeExemptedApps = {{ "com.example.app", 100, 0 }};
    ApplicationInstanceHandle::WriteApplicationMsgVector(data, freezeExemptedApps);
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ApplicationInstanceHandle::ReadApplicationInstanceVector(reply, freezeExemptedApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (freezeExemptedApps.empty()));
}

/**
 * @tc.name: TestOnGetPolicy
 * @tc.desc: Test ManageFreezeExemptedAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageFreezeExemptedAppsPluginTest, TestOnGetPolicy, TestSize.Level1)
{
    ManageFreezeExemptedAppsPlugin plugin;
    std::string adminName;
    std::string currentJsonData;
    std::string mergeJsonData;
    plugin.OnAdminRemove(adminName, currentJsonData, mergeJsonData, DEFAULT_USER_ID);

    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("bundleName");
    std::vector<ApplicationMsg> freezeExemptedApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ApplicationInstanceHandle::ReadApplicationInstanceVector(data, freezeExemptedApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (freezeExemptedApps.empty()));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS