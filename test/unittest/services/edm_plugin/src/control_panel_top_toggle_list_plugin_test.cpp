/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "control_panel_top_toggle_list_plugin.h"
#undef protected
#undef private

#include "edm_data_ability_utils_mock.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {

const std::vector<std::string> TEST_TOGGLE_LIST = {"cast", "hotspot"};
const std::vector<std::string> TEST_OLD_TOGGLE_LIST = {"nfc"};
constexpr uint32_t TEST_MAX_LIST_SIZE = 1000;

class ControlPanelTopToggleListPluginTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};

void ControlPanelTopToggleListPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ControlPanelTopToggleListPluginTest::TearDownTestSuite(void)
{
    EdmDataAbilityUtils::SetResult("");
    EdmDataAbilityUtils::ClearLastUpdatedValue();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: InitPlugin_Normal_Success
 * @tc.desc: Test InitPlugin sets code/name/size limit and needSave=false.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, InitPlugin_Normal_Success, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    auto pluginTemplate = std::make_shared<IPluginTemplate<ControlPanelTopToggleListPlugin,
        std::vector<std::string>>>();
    plugin.InitPlugin(pluginTemplate);
    EXPECT_EQ(pluginTemplate->GetCode(), EdmInterfaceCode::CONTROL_PANEL_TOP_TOGGLE_LIST);
    EXPECT_EQ(pluginTemplate->GetPolicyName(), PolicyName::POLICY_CONTROL_PANEL_TOP_TOGGLE_LIST);
    EXPECT_EQ(plugin.maxListSize_, TEST_MAX_LIST_SIZE);
    EXPECT_EQ(plugin.overMaxReturnErrCode_, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    // 覆盖策略：白名单不落 EDM RDB
    EXPECT_FALSE(pluginTemplate->NeedSavePolicy());
}

/**
 * @tc.name: OnBasicSetPolicy_Overwrite_Success
 * @tc.desc: Test overwrite semantics: currentData and mergeData both equal new data (not union).
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnBasicSetPolicy_Overwrite_Success, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    plugin.maxListSize_ = TEST_MAX_LIST_SIZE;
    std::vector<std::string> data = TEST_TOGGLE_LIST;
    std::vector<std::string> currentData = TEST_OLD_TOGGLE_LIST;
    std::vector<std::string> mergeData = TEST_OLD_TOGGLE_LIST;
    EdmDataAbilityUtils::SetResult("");

    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    // 覆盖：旧值 nfc 不再保留，不是并集
    EXPECT_EQ(currentData, TEST_TOGGLE_LIST);
    EXPECT_EQ(mergeData, TEST_TOGGLE_LIST);
}

/**
 * @tc.name: OnBasicSetPolicy_EmptyList_Success
 * @tc.desc: Test empty list is a valid overwrite (all croppable icons hidden).
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnBasicSetPolicy_EmptyList_Success, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    plugin.maxListSize_ = TEST_MAX_LIST_SIZE;
    std::vector<std::string> data;
    std::vector<std::string> currentData = TEST_OLD_TOGGLE_LIST;
    std::vector<std::string> mergeData = TEST_OLD_TOGGLE_LIST;
    EdmDataAbilityUtils::SetResult("");

    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(currentData.empty());
    EXPECT_TRUE(mergeData.empty());
}

/**
 * @tc.name: OnBasicSetPolicy_OverMax_Fail
 * @tc.desc: Test list exceeding max size returns PARAMETER_VERIFICATION_FAILED and keeps old data.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnBasicSetPolicy_OverMax_Fail, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    plugin.maxListSize_ = TEST_MAX_LIST_SIZE;
    plugin.overMaxReturnErrCode_ = EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    std::vector<std::string> data(TEST_MAX_LIST_SIZE + 1, "icon");
    std::vector<std::string> currentData = TEST_OLD_TOGGLE_LIST;
    std::vector<std::string> mergeData = TEST_OLD_TOGGLE_LIST;

    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
    EXPECT_EQ(currentData, TEST_OLD_TOGGLE_LIST);
    EXPECT_EQ(mergeData, TEST_OLD_TOGGLE_LIST);
}

/**
 * @tc.name: OnBasicSetPolicy_UpdateSettingsDataFail_Fail
 * @tc.desc: Test settingsdata write failure returns EXECUTE_TIME_OUT.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnBasicSetPolicy_UpdateSettingsDataFail_Fail, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    plugin.maxListSize_ = TEST_MAX_LIST_SIZE;
    std::vector<std::string> data = TEST_TOGGLE_LIST;
    std::vector<std::string> currentData;
    std::vector<std::string> mergeData;
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");

    ErrCode ret = plugin.OnBasicSetPolicy(data, currentData, mergeData, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: OnGetPolicy_DataShareFail_ReturnError
 * @tc.desc: Test query returns execute error when settingsdata read fails.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnGetPolicy_DataShareFail_ReturnError, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelTopToggleListPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("test Failed");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}

/**
 * @tc.name: OnGetPolicy_EmptyValue_ReturnEmpty
 * @tc.desc: Test query returns empty list when settingsdata field is absent.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnGetPolicy_EmptyValue_ReturnEmpty, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelTopToggleListPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("test value nullptr");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: OnGetPolicy_CommaSeparated_Success
 * @tc.desc: Test query splits the comma-separated settingsdata value into a list.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, OnGetPolicy_CommaSeparated_Success, TestSize.Level1)
{
    auto plugin = std::make_shared<ControlPanelTopToggleListPlugin>();
    std::string policyData;
    MessageParcel data;
    MessageParcel reply;
    EdmDataAbilityUtils::SetResult("control_panel_top_toggle_list");

    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(reply.ReadInt32(), ERR_OK);
    std::vector<std::string> result;
    reply.ReadStringVector(&result);
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "cast");
    EXPECT_EQ(result[1], "hotspot");
}

/**
 * @tc.name: WriteToggleListToSettingsData_Normal_Success
 * @tc.desc: Test serialization and settingsdata write succeed for normal list.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, WriteToggleListToSettingsData_Normal_Success, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    EdmDataAbilityUtils::SetResult("");

    ErrCode ret = plugin.WriteToggleListToSettingsData(TEST_TOGGLE_LIST, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: WriteToggleListToSettingsData_CommaJoined_Success
 * @tc.desc: Test settingsdata value is a comma-separated string without JSON brackets.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, WriteToggleListToSettingsData_CommaJoined_Success, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    EdmDataAbilityUtils::SetResult("");

    ErrCode ret = plugin.WriteToggleListToSettingsData(TEST_TOGGLE_LIST, DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(EdmDataAbilityUtils::GetLastUpdatedValue(), "cast,hotspot");
}

/**
 * @tc.name: WriteToggleListToSettingsData_Fail_Fail
 * @tc.desc: Test settingsdata write failure maps to EXECUTE_TIME_OUT.
 * @tc.type: FUNC
 */
HWTEST_F(ControlPanelTopToggleListPluginTest, WriteToggleListToSettingsData_Fail_Fail, TestSize.Level1)
{
    ControlPanelTopToggleListPlugin plugin;
    EdmDataAbilityUtils::SetResult("SYSTEM_ABNORMALLY");

    ErrCode ret = plugin.WriteToggleListToSettingsData(TEST_TOGGLE_LIST, DEFAULT_USER_ID);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS