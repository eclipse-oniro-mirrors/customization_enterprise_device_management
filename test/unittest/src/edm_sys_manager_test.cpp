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

#include <gtest/gtest.h>
#include "edm_sys_manager.h"
#include "system_ability_definition.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class EdmSysManagerTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestGetRemoteObjectOfSystemAbility
 * @tc.desc: Test GetRemoteObjectOfSystemAbility function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmSysManagerTest, TestGetRemoteObjectOfSystemAbility, TestSize.Level1)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    ASSERT_TRUE(remoteObject != nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS