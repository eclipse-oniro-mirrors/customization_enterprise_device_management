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

#include "disallow_mobile_data_plugin.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iedm_cellular_data_manager.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "plugin_singleton.h"
#include "telephony_errors.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

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

void DisallowMobileDataTest::SetUp()
{
    IEdmCellularDataManager::iInstance_ = cellularDataManagerMock_.get();
}

void DisallowMobileDataTest::TearDown()
{
    cellularDataManagerMock_.reset();
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

    EXPECT_CALL(*cellularDataManagerMock_, EnableCellularData(_))
        .WillOnce(Return(Telephony::TELEPHONY_ERR_SUCCESS));

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

    EXPECT_CALL(*cellularDataManagerMock_, EnableCellularData(_))
        .WillOnce(Return(Telephony::TELEPHONY_ERR_SUCCESS));

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

    EXPECT_CALL(*cellularDataManagerMock_, EnableCellularData(_))
        .WillOnce(Return(Telephony::TELEPHONY_ERR_SUCCESS));

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

/**
 * @tc.name: TestOnHandlePolicyTypeNotSet
 * @tc.desc: Test OnHandlePolicy when type is not SET.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyTypeNotSet, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::GET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicySetParameterFail
 * @tc.desc: Test OnHandlePolicy when EnableCellularData fails for disallow.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicySetParameterFail, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(true);
    EXPECT_CALL(*cellularDataManagerMock_, EnableCellularData(_))
        .WillOnce(Return(-1));
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyCellularDataNull
 * @tc.desc: Test OnHandlePolicy when cellularDataManager is null.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyCellularDataNull, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(true);
    IEdmCellularDataManager::iInstance_ = nullptr;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    IEdmCellularDataManager::iInstance_ = cellularDataManagerMock_.get();
}

/**
 * @tc.name: TestOnHandlePolicyEnableCellularDataFail
 * @tc.desc: Test OnHandlePolicy when EnableCellularData fails.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyEnableCellularDataFail, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(true);
    EXPECT_CALL(*cellularDataManagerMock_, EnableCellularData(_))
        .WillOnce(Return(-1));
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicySetNoneFail
 * @tc.desc: Test OnHandlePolicy when setting none policy succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicySetNoneFail, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::DISALLOW_FLAG);
    data.WriteBool(false);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnHandlePolicyForceOpenInvalid
 * @tc.desc: Test OnHandlePolicy when forceOpen value is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyForceOpenInvalid, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::FORCE_FLAG);
    data.WriteInt32(999);
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnHandlePolicyForceCellularDataNull
 * @tc.desc: Test OnHandlePolicy when cellularDataManager is null for force open.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyForceCellularDataNull, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(EdmConstants::MobileData::FORCE_FLAG);
    data.WriteInt32(EdmConstants::MobileData::FORCE_OPEN);
    IEdmCellularDataManager::iInstance_ = nullptr;
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    IEdmCellularDataManager::iInstance_ = cellularDataManagerMock_.get();
}

/**
 * @tc.name: TestOnHandlePolicyForceEnableFail
 * @tc.desc: Test OnHandlePolicy when force open is rejected due to disallow state.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyForceEnableFail, TestSize.Level1)
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
    ASSERT_EQ(ret, EdmReturnErrCode::ENTERPRISE_POLICES_DENIED);
    system::SetParameter("persist.edm.mobile_data_policy", "none");
}

/**
 * @tc.name: TestOnHandlePolicyInvalidFlag
 * @tc.desc: Test OnHandlePolicy when flag is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnHandlePolicyInvalidFlag, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOWED_MOBILE_DATA);
    HandlePolicyData handlePolicyData{"", "", false};
    MessageParcel data;
    MessageParcel reply;
    data.WriteString("invalid_flag");
    ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
    ASSERT_EQ(ret, EdmReturnErrCode::SYSTEM_ABNORMALLY);
}

/**
 * @tc.name: TestOnAdminRemoveSuccess
 * @tc.desc: Test OnAdminRemove success.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnAdminRemoveSuccess, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    ErrCode ret = plugin->OnAdminRemove("test_admin", "disallow", "disallow", DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: TestOnAdminRemoveSetParameterFail
 * @tc.desc: Test OnAdminRemove resets mobile data policy to none.
 * @tc.type: FUNC
 */
HWTEST_F(DisallowMobileDataTest, TestOnAdminRemoveSetParameterFail, TestSize.Level1)
{
    std::shared_ptr<DisallowMobileDataPlugin> plugin = std::make_shared<DisallowMobileDataPlugin>();
    system::SetParameter("persist.edm.mobile_data_policy", "disallow");
    ErrCode ret = plugin->OnAdminRemove("test_admin", "disallow", "disallow", DEFAULT_USER_ID);
    ASSERT_EQ(ret, ERR_OK);
    std::string value = system::GetParameter("persist.edm.mobile_data_policy", "");
    ASSERT_EQ(value, "none");
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
