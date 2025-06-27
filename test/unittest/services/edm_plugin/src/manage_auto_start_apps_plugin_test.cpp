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

#define protected public
#define private public
#include "manage_auto_start_apps_plugin_test.h"
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
#include "install_plugin.h"
#include "uninstall_plugin.h"
#include "utils.h"
#include "func_code.h"
#include "manage_auto_start_app_info.h"
#include "manage_auto_start_apps_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string RIGHT_TEST_BUNDLE = "com.example.l3jsdemo/com.example.l3jsdemo.MainAbility";
const std::string ERROR_TEST_BUNDLE = "com.example.l3jsdemo/com.example.l3jsdemo.ErrorAbility";
const std::string INVALID_TEST_BUNDLE = "com.example.l3jsdemo.com.example.l3jsdemo.ErrorAbility";
const std::string HAP_FILE_PATH = "/data/test/resource/enterprise_device_management/hap/right.hap";
const std::string BOOT_OEM_MODE = "const.boot.oemmode";
const std::string DEVELOP_PARAM = "rd";
const std::string USER_MODE = "user";
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
 * @tc.name: TestOnHandlePolicyAddFailWithNullData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnHandlePolicy add when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnHandlePolicyAddFailWithNullData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<std::string> autoStartApps;
    data.WriteStringVector(autoStartApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNullData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnHandlePolicy remove when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnHandlePolicyRemoveFailWithNullData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    std::vector<std::string> autoStartApps;
    data.WriteStringVector(autoStartApps);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyFailWithOversizeData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnHandlePolicy when data is oversize.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnHandlePolicyFailWithOversizeData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    HandlePolicyData policyData;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> dataStr;
    for (int i = 0; i < 15; i++) {
        std::string str = "test/test" + std::to_string(i);
        dataStr.push_back(str);
    }
    data.WriteStringVector(dataStr);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnHandlePolicyAddFailWithNotExistedData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnHandlePolicy add when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnHandlePolicyAddFailWithNotExistedData, TestSize.Level1)
{
    std::vector<std::string> autoStartApps = {"com.not.existed/com.not.exxisted"};
    ManageAutoStartAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    data.WriteStringVector(autoStartApps);
    HandlePolicyData policyData;

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ErrCode res;
    reply.ReadInt32(res);
    ASSERT_TRUE(res == EdmReturnErrCode::PARAM_ERROR);
    ASSERT_TRUE(ret == res);
}

/**
 * @tc.name: TestOnHandlePolicyRemoveFailWithNotExistedData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnHandlePolicy remove when app is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnHandlePolicyRemoveFailWithNotExistedData, TestSize.Level1)
{
    std::vector<std::string> autoStartApps = {"com.not.existed/com.not.exxisted"};
    ManageAutoStartAppsPlugin plugin;
    MessageParcel data;
    MessageParcel reply;
    data.WriteStringVector(autoStartApps);
    HandlePolicyData policyData;
    ArrayStringSerializer::GetInstance()->Serialize(autoStartApps, policyData.policyData);

    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    ErrCode ret = plugin.OnHandlePolicy(funcCode, data, reply, policyData, DEFAULT_USER_ID);
    ErrCode res;
    reply.ReadInt32(res);
    ASSERT_TRUE(res == ERR_OK);
    ASSERT_TRUE(ret == res);
}

/**
 * @tc.name: TestOnGetPolicyFail
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnGetPolicyFail, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> autoStartApps;
    data.WriteString("bundleInfo");
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    reply.ReadStringVector(&autoStartApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (autoStartApps.empty()));
}

/**
 * @tc.name: TestGetDisallowModifyFail
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestGetDisallowModifyFail, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    std::vector<std::string> autoStartApps;
    data.WriteString("disallowModity");
    data.WriteString("com.test1");
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    bool disallowModify = reply.ReadBool();
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (!disallowModify));
}

/**
 * @tc.name: TestOnAdminRemoveDoneFail
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnAdminRemoveDone.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnAdminRemoveDoneFail, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::string adminName;
    std::string currentJsonData;
    plugin.OnAdminRemoveDone(adminName, currentJsonData, DEFAULT_USER_ID);

    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("bundleInfo");
    std::vector<std::string> autoStartApps;
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    reply.ReadStringVector(&autoStartApps);
    ASSERT_TRUE((ret == EdmReturnErrCode::SYSTEM_ABNORMALLY) || (autoStartApps.empty()));
}

/**
 * @tc.name: TestOnSetPolicySucWithNullData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnSetPolicySucWithNullData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data;
    bool disallowModify = false;
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnSetPolicyFailWithbundleExceededLimit
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when budle is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnSetPolicyFailWithbundleExceededLimit, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data;
    for (int i = 0; i < 15; i++) {
        std::string str = "test/test" + std::to_string(i);
        data.push_back(str);
    }
    bool disallowModify = false;
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    ErrCode ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyFailWithbundleNotExist
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when budle is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnSetPolicyFailWithbundleNotExist, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data = {RIGHT_TEST_BUNDLE};
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    bool disallowModify = false;
    ErrCode ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicyFailWithInvalidData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnSetPolicyFailWithInvalidData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data = {INVALID_TEST_BUNDLE};
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    bool disallowModify = false;
    ErrCode ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::PARAM_ERROR);
}

/**
 * @tc.name: TestOnSetPolicySuc
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when budle is existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnSetPolicySuc, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        InstallPlugin installPlugin;
        InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
        MessageParcel reply;
        ErrCode ret = installPlugin.OnSetPolicy(param, reply);
        EXPECT_TRUE(ret == ERR_OK);

        ManageAutoStartAppsPlugin plugin;
        plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
        std::vector<std::string> data = {RIGHT_TEST_BUNDLE, ERROR_TEST_BUNDLE, INVALID_TEST_BUNDLE};
        std::vector<ManageAutoStartAppInfo> currentData;
        std::vector<ManageAutoStartAppInfo> mergeData;
        bool disallowModify = false;
        ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        std::string policyData;
        ManageAutoStartAppsSerializer::GetInstance()->Serialize(currentData, policyData);
        MessageParcel parcel;
        MessageParcel getReply;
        parcel.WriteString("bundleInfo");
        ret = plugin.OnGetPolicy(policyData, parcel, getReply, DEFAULT_USER_ID);
        std::vector<std::string> res;
        EXPECT_TRUE(ret == ERR_OK);
        EXPECT_TRUE(getReply.ReadInt32() == ERR_OK);
        getReply.ReadStringVector(&res);
        EXPECT_TRUE(res.size() >= 1);
        EXPECT_TRUE(std::find(res.begin(), res.end(), RIGHT_TEST_BUNDLE) != res.end());

        std::vector<std::string> removeData = {RIGHT_TEST_BUNDLE, ERROR_TEST_BUNDLE, INVALID_TEST_BUNDLE};
        mergeData.clear();
        ret = plugin.OnRemovePolicy(removeData, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        MessageParcel removeReply;
        std::string afterRemovePolicyData;
        ManageAutoStartAppsSerializer::GetInstance()->Serialize(currentData, afterRemovePolicyData);
        parcel.WriteString("bundleInfo");
        ret = plugin.OnGetPolicy(afterRemovePolicyData, parcel, removeReply, DEFAULT_USER_ID);
        std::vector<std::string> afterRemove;
        EXPECT_TRUE(ret == ERR_OK);
        EXPECT_TRUE(removeReply.ReadInt32() == ERR_OK);
        removeReply.ReadStringVector(&afterRemove);
        EXPECT_TRUE(afterRemove.size() == 0);

        UninstallPlugin uninstallPlugin;
        UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
        MessageParcel uninstallReply;
        ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
        EXPECT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnGetPolicySuc
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnGetPolicy.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnGetPolicySuc, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    std::string policyData = RIGHT_TEST_BUNDLE;
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("bundleInfo");
    ErrCode ret = plugin.OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicySucWithNullData
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnRemovePolicy when data is empty.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnRemovePolicySucWithNullData, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data;
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicyFileWithErrBundle
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnRemovePolicy when budle is not existed.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnRemovePolicyFileWithErrBundle, TestSize.Level1)
{
    ManageAutoStartAppsPlugin plugin;
    plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
    std::vector<std::string> data = {ERROR_TEST_BUNDLE};
    std::vector<ManageAutoStartAppInfo> currentData;
    std::vector<ManageAutoStartAppInfo> mergeData;
    ErrCode ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestOnRemovePolicySuc
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnRemovePolicySuc, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        InstallPlugin installPlugin;
        InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
        MessageParcel reply;
        ErrCode ret = installPlugin.OnSetPolicy(param, reply);
        EXPECT_TRUE(ret == ERR_OK);

        ManageAutoStartAppsPlugin plugin;
        plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
        std::vector<std::string> data = {RIGHT_TEST_BUNDLE};
        std::vector<ManageAutoStartAppInfo> currentData;
        std::vector<ManageAutoStartAppInfo> mergeData;
        bool disallowModify = false;
        ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        data = {INVALID_TEST_BUNDLE};
        ManageAutoStartAppInfo info;
        info.SetBundleName(INVALID_TEST_BUNDLE);
        info.SetAbilityName("");
        currentData.push_back(info);
        ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        data = {RIGHT_TEST_BUNDLE};
        ManageAutoStartAppInfo info1;
        info1.SetUniqueKey(RIGHT_TEST_BUNDLE);
        currentData = {info1};
        ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        UninstallPlugin uninstallPlugin;
        UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
        MessageParcel uninstallReply;
        ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
        EXPECT_TRUE(ret == ERR_OK);
    }
}

/**
 * @tc.name: TestOnRemovePolicySucAlreadyUninstall
 * @tc.desc: Test ManageAutoStartAppsPlugin::OnSetPolicy when hap already uninstall.
 * @tc.type: FUNC
 */
HWTEST_F(ManageAutoStartAppsPluginTest, TestOnRemovePolicySucAlreadyUninstall, TestSize.Level1)
{
    std::string developDeviceParam = system::GetParameter(BOOT_OEM_MODE, USER_MODE);
    if (developDeviceParam == DEVELOP_PARAM) {
        InstallPlugin installPlugin;
        InstallParam param = {{HAP_FILE_PATH}, DEFAULT_USER_ID, 0};
        MessageParcel reply;
        ErrCode ret = installPlugin.OnSetPolicy(param, reply);
        EXPECT_TRUE(ret == ERR_OK);

        ManageAutoStartAppsPlugin plugin;
        plugin.maxListSize_ = EdmConstants::AUTO_START_APPS_MAX_SIZE;
        std::vector<std::string> data = {RIGHT_TEST_BUNDLE};
        std::vector<ManageAutoStartAppInfo> currentData;
        std::vector<ManageAutoStartAppInfo> mergeData;
        bool disallowModify = false;
        ret = plugin.OnSetPolicy(data, disallowModify, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);

        UninstallPlugin uninstallPlugin;
        UninstallParam uninstallParam = {"com.example.l3jsdemo", DEFAULT_USER_ID, false};
        MessageParcel uninstallReply;
        ret = uninstallPlugin.OnSetPolicy(uninstallParam, uninstallReply);
        EXPECT_TRUE(ret == ERR_OK);

        data = {RIGHT_TEST_BUNDLE};
        mergeData.clear();
        ret = plugin.OnRemovePolicy(data, currentData, mergeData, DEFAULT_USER_ID);
        EXPECT_TRUE(ret == ERR_OK);
    }
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS