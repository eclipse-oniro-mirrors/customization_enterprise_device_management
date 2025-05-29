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

#include "disallow_mobile_data_plugin_test.h"

#include "core_service_client.h"
#include "disallow_mobile_data_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "plugin_singleton.h"
#include "telephony_types.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void DisallowMobileDataTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void DisallowMobileDataTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_001
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_001, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"false", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_002
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_002, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"true", "", true};
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_003
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_003, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"false", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(true);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_004
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_004, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"true", "", true};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_005
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_005, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::FORCE_FLAG);
    data.WriteInt32(EdmConstants::MobileData::FORCE_OPEN);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDisallowMobileDataSuccess_006
 * @tc.desc: Test DisallowMobileDataPlugin::OnSetPolicy function sucess.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestDisallowMobileDataSuccess_006, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::FORCE_FLAG);
    data.WriteInt32(EdmConstants::MobileData::FORCE_OPEN);
    system::SetParameter("persist.edm.mobile_data_policy", "disallow");
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_TRUE(ret == EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
    system::SetParameter("persist.edm.mobile_data_policy", "none");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS