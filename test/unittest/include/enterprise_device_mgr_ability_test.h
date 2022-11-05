/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H
#define EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H

#include <gtest/gtest.h>
#include "enterprise_device_mgr_ability.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class EnterpriseDeviceMgrAbilityTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    void PrepareBeforeHandleDevicePolicy();
    int HandleDevicePolicyFuncTest001(void);
    int HandleDevicePolicyFuncTest002(void);
    int HandleDevicePolicyFuncTest003(void);
    int HandleDevicePolicyFuncTest004(void);
    int HandleDevicePolicyFuncTest005(void);
    int HandleDevicePolicyFuncTest006(void);
    int HandleDevicePolicyFuncTest007(void);
    int HandleDevicePolicyFuncTest008(void);
    int GetDevicePolicyFuncTest001(void);
    int GetDevicePolicyFuncTest002(void);
protected:
    sptr<EnterpriseDeviceMgrAbility> edmMgr_;
    std::shared_ptr<IPlugin> plugin_;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H