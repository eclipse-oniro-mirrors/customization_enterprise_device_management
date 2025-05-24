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

#include "set_apn_plugin_test.h"

#include "edm_ipc_interface_code.h"
#include "plugin_singleton.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
const std::string ADD_FLAG = "AddApn";
const std::string UPDATE_FLAG = "UpdateApn";
const std::string SET_PREFER_FLAG = "SetPreferApn";
const std::string QUERY_ID_FLAG = "QueryApnIds";
const std::string QUERY_INFO_FLAG = "QueryApn";
}
std::string g_testApnId = "-1";
void SetApnPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
}

void SetApnPluginTest::TearDownTestSuite(void)
{
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

static void AddTestData(MessageParcel &data)
{
    data.WriteString("TEST_ADD_PROFILE_NAME");
    data.WriteString("TEST_ADD_APN");
    data.WriteString("TEST_ADD_MCC");
    data.WriteString("TEST_ADD_MNC");
    data.WriteString("TEST_ADD_AUTH_USER");
    data.WriteString("TEST_ADD_APN_TYPES");
    data.WriteString("TEST_ADD_PROXY_IP_ADDRESS");
    data.WriteString("TEST_ADD_MMS_IP_ADDRESS");
}

static void UpdateTestData(MessageParcel &data)
{
    data.WriteString("TEST_UPDATE_PROFILE_NAME");
    data.WriteString("TEST_UPDATE_APN");
    data.WriteString("TEST_UPDATE_MCC");
    data.WriteString("TEST_UPDATE_MNC");
    data.WriteString("TEST_UPDATE_AUTH_USER");
    data.WriteString("TEST_UPDATE_APN_TYPES");
    data.WriteString("TEST_UPDATE_PROXY_IP_ADDRESS");
    data.WriteString("TEST_UPDATE_MMS_IP_ADDRESS");
}

/**
 * @tc.name: TestAddApn
 * @tc.desc: Test SetApnPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestAddApn, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(ADD_FLAG);
    AddTestData(data);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestQueryApnId
 * @tc.desc: Test SetApnPlugin::OnQueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestQueryApnId, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(QUERY_ID_FLAG);
    AddTestData(data);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::vector<std::string> val;
    ASSERT_TRUE(reply.ReadStringVector(&val) == ERR_OK);
    g_testApnId = val[0];
    ASSERT_TRUE(std::stoi(g_testApnId) >= 0);
}

/**
 * @tc.name: TestQueryApnInfoForAdd
 * @tc.desc: Test SetApnPlugin::OnQueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestQueryApnInfoForAdd, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(QUERY_INFO_FLAG);
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string profileName;
    ASSERT_TRUE(reply.ReadString(profileName));
    ASSERT_TRUE(profileName == "TEST_ADD_PROFILE_NAME");
}

/**
 * @tc.name: TestUpdateApn
 * @tc.desc: Test SetApnPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestUpdateApn, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(UPDATE_FLAG);
    data.WriteString(g_testApnId);
    UpdateTestData(data);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestQueryApnInfoForUpdate
 * @tc.desc: Test SetApnPlugin::OnQueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestQueryApnInfoForUpdate, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(QUERY_INFO_FLAG);
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    std::string profileName;
    ASSERT_TRUE(reply.ReadString(profileName));
    ASSERT_TRUE(profileName == "TEST_UPDATE_PROFILE_NAME");
}

/**
 * @tc.name: TestSetPreferApn
 * @tc.desc: Test SetApnPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestSetPreferApn, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(SET_PREFER_FLAG);
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDeleteApn
 * @tc.desc: Test SetApnPlugin::OnRemovePolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestDeleteApn, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS