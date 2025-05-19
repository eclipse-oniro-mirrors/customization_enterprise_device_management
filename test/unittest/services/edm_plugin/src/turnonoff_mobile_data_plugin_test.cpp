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

 #include "core_service_client.h"
 #include "turnonoff_mobile_data_plugin_test.h"
 #include "edm_ipc_interface_code.h"
 #include "parameters.h"
 #include "plugin_singleton.h"
 #include "utils.h"
 #include "telephony_types.h"
   
 using namespace testing::ext;
   
 namespace OHOS {
 namespace EDM {
 namespace TEST {
 void TurnOnOffMobileDataTest::SetUpTestSuite(void)
 {
     Utils::SetEdmInitialEnv();
 }
   
 void TurnOnOffMobileDataTest::TearDownTestSuite(void)
 {
     Utils::ResetTokenTypeAndUid();
     ASSERT_TRUE(Utils::IsOriginalUTEnv());
     std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
 }
 
 bool TurnOnOffMobileDataTest::HasSimCard()
 {
     bool hasSimCard = false;
     if (Telephony::CoreServiceClient::GetInstance().GetProxy() == nullptr) {
        return hasSimCard;
     }
     int32_t slotCount = Telephony::CoreServiceClient::GetInstance().GetMaxSimCount();

     for (int32_t i = 0; i<slotCount; i++) {
         int32_t id = Telephony::CoreServiceClient::GetInstance().GetSimId(i);
         if (id > 0) {
            hasSimCard = true;
            break;
         }
     }
     return hasSimCard;
 }

 /**
  * @tc.name: TestForceTurnOnMobileDataSuccess
  * @tc.desc: Test TurnOnMobileDataPlugin::OnSetPolicy function sucess.
  * @tc.type: FUNC
  */
 HWTEST_F(TurnOnOffMobileDataTest, TestForceTurnOnMobileDataSuccess, TestSize.Level1)
 {
     std::shared_ptr<IPlugin> plugin = TurnOnOffMobileDataPlugin::GetPlugin();
     uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TURNONOFF_MOBILE_DATA);
     HandlePolicyData handlePolicyData{"false", "", false};
     MessageParcel data;
     MessageParcel reply;
     data.WriteBool(true);
     ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
     if (TurnOnOffMobileDataTest::HasSimCard()) {
        ASSERT_TRUE(ret == ERR_OK);
     } else {
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
     }
 }
   
 /**
  * @tc.name: TestTurnOnMobileDataSuccess
  * @tc.desc: Test TurnOnMobileDataPlugin::OnSetPolicy function sucess.
  * @tc.type: FUNC
  */
 HWTEST_F(TurnOnOffMobileDataTest, TestTurnOnMobileDataSuccess, TestSize.Level1)
 {
     std::shared_ptr<IPlugin> plugin = TurnOnOffMobileDataPlugin::GetPlugin();
     uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::TURNONOFF_MOBILE_DATA);
     HandlePolicyData handlePolicyData{"false", "", false};
     MessageParcel data;
     MessageParcel reply;
     data.WriteBool(false);
     ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
     if (TurnOnOffMobileDataTest::HasSimCard()) {
        ASSERT_TRUE(ret == ERR_OK);
     } else {
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
     }
 }

  /**
  * @tc.name: TestTurnOffMobileDataSuccess
  * @tc.desc: Test TurnOnMobileDataPlugin::OnSetPolicy function sucess.
  * @tc.type: FUNC
  */
 HWTEST_F(TurnOnOffMobileDataTest, TestTurnOffMobileDataSuccess, TestSize.Level1)
 {
     std::shared_ptr<IPlugin> plugin = TurnOnOffMobileDataPlugin::GetPlugin();
     uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::TURNONOFF_MOBILE_DATA);
     HandlePolicyData handlePolicyData{"false", "", false};
     MessageParcel data;
     MessageParcel reply;
     ErrCode ret = plugin->OnHandlePolicy(code, data, reply, handlePolicyData, DEFAULT_USER_ID);
     if (TurnOnOffMobileDataTest::HasSimCard()) {
        ASSERT_TRUE(ret == ERR_OK);
     } else {
        ASSERT_TRUE(ret == EdmReturnErrCode::SYSTEM_ABNORMALLY);
     }
 }
 } // namespace TEST
 } // namespace EDM
 } // namespace OHOS