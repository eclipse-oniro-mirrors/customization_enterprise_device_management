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
#include "core_service_client.h"
#include "telephony_types.h"
#include "parameters.h"

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
constexpr int32_t ADD_FIELD_SIZE = 8;
constexpr int32_t UPDATE_FIELD_SIZE = 2;
constexpr int32_t OPKEY_QUERY_SIZE = 1;
std::string g_testApnId = "-1";
}

bool SetApnPluginTest::HasValidSimCard(std::vector<int32_t> &slotIds)
{
    if (Telephony::CoreServiceClient::GetInstance().GetProxy() == nullptr) {
        return false;
    }
    int32_t slotCount = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();
    bool hasValidSimCard = false;
    for (int32_t i = 0; i < slotCount; i++) {
        if (!Telephony::CoreServiceClient::GetInstance().IsSimActive(i)) {
            continue;
        }
        int32_t id = Telephony::CoreServiceClient::GetInstance().GetSimId(i);
        if (id >= 0) {
            hasValidSimCard = true;
            slotIds.push_back(i);
        }
    }
    return hasValidSimCard;
}

void SetApnPluginTest::AddTestData(MessageParcel &data)
{
    data.WriteInt32(ADD_FIELD_SIZE);
    data.WriteString("profile_name");
    data.WriteString("apn");
    data.WriteString("mcc");
    data.WriteString("mnc");
    data.WriteString("auth_user");
    data.WriteString("apn_types");
    data.WriteString("proxy_ip_address");
    data.WriteString("mms_ip_address");

    data.WriteString("TEST_ADD_PROFILE_NAME");
    data.WriteString("TEST_ADD_APN");
    data.WriteString(system::GetParameter("telephony.sim.opkey0", ""));
    data.WriteString("");
    data.WriteString("TEST_ADD_AUTH_USER");
    data.WriteString("TEST_ADD_APN_TYPES");
    data.WriteString("TEST_ADD_PROXY_IP_ADDRESS");
    data.WriteString("TEST_ADD_MMS_IP_ADDRESS");
}

void SetApnPluginTest::UpdateTestData(MessageParcel &data)
{
    data.WriteInt32(UPDATE_FIELD_SIZE);
    data.WriteString("profile_name");
    data.WriteString("apn");
    data.WriteString("TEST_UPDATE_PROFILE_NAME");
    data.WriteString("TEST_UPDATE_APN");
}

void SetApnPluginTest::GetApnId()
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteString(QUERY_ID_FLAG);
    AddTestData(data);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    if (ret != ERR_OK) {
        EDMLOGE("SetApnPluginTest GetApnId failed");
        return;
    }
    ret = reply.ReadInt32();
    if (ret == ERR_OK && reply.ReadInt32() > 0) {
        g_testApnId = reply.ReadString();
    }
}

void SetApnPluginTest::GetApnId(const std::string &opkey, std::string &apnId)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteString(QUERY_ID_FLAG);
    data.WriteInt32(OPKEY_QUERY_SIZE);
    data.WriteString("opkey");
    data.WriteString(opkey);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    if (ret != ERR_OK) {
        EDMLOGE("SetApnPluginTest GetApnId failed");
        return;
    }
    ret = reply.ReadInt32();
    if (ret == ERR_OK && reply.ReadInt32() > 0) {
        apnId = reply.ReadString();
    }
}

void SetApnPluginTest::AddApn()
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(ADD_FLAG);
    AddTestData(data);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    if (ret != ERR_OK) {
        EDMLOGE("SetApnPluginTest AddApn failed");
        return;
    }
    GetApnId();
}

void SetApnPluginTest::DeleteApn()
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    if (ret != ERR_OK) {
        EDMLOGE("SetApnPluginTest AddApn failed");
    }
}

void SetApnPluginTest::SetUpTestSuite(void)
{
    Utils::SetEdmServiceEnable();
    Utils::SetEdmInitialEnv();
    AddApn();
}

void SetApnPluginTest::TearDownTestSuite(void)
{
    DeleteApn();
    Utils::SetEdmServiceDisable();
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestQueryApnInfoForAdd
 * @tc.desc: Test SetApnPlugin::OnQueryPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestQueryApnInfoForAdd, TestSize.Level1)
{
    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    std::string policyData;
    MessageParcel data;
    data.WriteString(QUERY_INFO_FLAG);
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    int size = reply.ReadInt32();
    std::vector<std::string> keys;
    for (int idx = 0; idx < size; idx++) {
        keys.push_back(reply.ReadString());
    }
    std::vector<std::string> values;
    for (int idx = 0; idx < size; idx++) {
        values.push_back(reply.ReadString());
    }
    ASSERT_TRUE(keys[0] == "apn");
    ASSERT_TRUE(values[0] == "TEST_ADD_APN");
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
    std::string policyData;
    MessageParcel data;
    data.WriteString(QUERY_INFO_FLAG);
    data.WriteString(g_testApnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnGetPolicy(policyData, data, reply, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_TRUE(reply.ReadInt32() == ERR_OK);
    int size = reply.ReadInt32();
    std::vector<std::string> keys;
    for (int idx = 0; idx < size; idx++) {
        keys.push_back(reply.ReadString());
    }
    std::vector<std::string> values;
    for (int idx = 0; idx < size; idx++) {
        values.push_back(reply.ReadString());
    }
    ASSERT_TRUE(keys[0] == "apn");
    ASSERT_TRUE(values[0] == "TEST_UPDATE_APN");
}

/**
 * @tc.name: TestSetPreferApn
 * @tc.desc: Test SetApnPlugin::OnSetPolicy function.
 * @tc.type: FUNC
 */
HWTEST_F(SetApnPluginTest, TestSetPreferApn, TestSize.Level1)
{
    std::vector<int32_t> slotIds;
    if (!HasValidSimCard(slotIds)) {
        return;
    }

    std::string opkey = system::GetParameter(std::string("telephony.sim.opkey") + std::to_string(slotIds[0]), "");
    std::string apnId;
    GetApnId(opkey, apnId);
    ASSERT_TRUE(apnId.empty() == false);

    std::shared_ptr<SetApnPlugin> plugin = std::make_shared<SetApnPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_APN_INFO);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    data.WriteString(SET_PREFER_FLAG);
    data.WriteString(apnId);
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS