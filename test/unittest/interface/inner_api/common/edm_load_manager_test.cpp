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
#include <system_ability_definition.h>
#include <iremote_object.h>

#define private public
#define protected public
#include "edm_load_manager.h"
#undef private
#undef protected

#include "edm_errors.h"
#include "edm_load_callback.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class EdmLoadManagerTest : public testing::Test {};

/**
 * @tc.name: TestGetInstance
 * @tc.desc: Test EdmLoadManager::GetInstance returns one and the same instance.
 * @tc.type: FUNC
 */
HWTEST_F(EdmLoadManagerTest, TestGetInstance, TestSize.Level1)
{
    auto &first = EdmLoadManager::GetInstance();
    auto &second = EdmLoadManager::GetInstance();
    EXPECT_EQ(&first, &second);
}

/**
 * @tc.name: TestLoadSystemAbilitySuccessThenWait
 * @tc.desc: Test the load state turns successful and WaitLoadStateChange returns without waiting.
 * @tc.type: FUNC
 */
HWTEST_F(EdmLoadManagerTest, TestLoadSystemAbilitySuccessThenWait, TestSize.Level1)
{
    EdmLoadManager manager;
    manager.InitLoadState();
    manager.LoadSystemAbilitySuccess();
    EXPECT_EQ(manager.WaitLoadStateChange(), ERR_OK);
}

/**
 * @tc.name: TestInitLoadStateThenWaitTimeout
 * @tc.desc: Test WaitLoadStateChange reports a load failure when the state never turns ready.
 * @tc.type: FUNC
 */
HWTEST_F(EdmLoadManagerTest, TestInitLoadStateThenWaitTimeout, TestSize.Level1)
{
    EdmLoadManager manager;
    manager.InitLoadState();
    EXPECT_EQ(manager.WaitLoadStateChange(), ERR_EDM_SA_LOAD_FAILED);
}

/**
 * @tc.name: TestLoadSystemAbilityFailAfterSuccess
 * @tc.desc: Test a failed load clears a previously set success state.
 * @tc.type: FUNC
 */
HWTEST_F(EdmLoadManagerTest, TestLoadSystemAbilityFailAfterSuccess, TestSize.Level1)
{
    EdmLoadManager manager;
    manager.LoadSystemAbilitySuccess();
    manager.LoadSystemAbilityFail();
    EXPECT_FALSE(manager.state_);
    manager.LoadSystemAbilitySuccess();
    EXPECT_TRUE(manager.state_);
}

/**
 * @tc.name: TestCallbackSetsLoadState
 * @tc.desc: Test EdmLoadCallback forwards the SA load result into the EdmLoadManager state.
 * @tc.type: FUNC
 */
HWTEST_F(EdmLoadManagerTest, TestCallbackSetsLoadState, TestSize.Level1)
{
    EdmLoadCallback callback;
    sptr<IRemoteObject> remoteObject = nullptr;
    callback.OnLoadSystemAbilitySuccess(ENTERPRISE_DEVICE_MANAGER_SA_ID, remoteObject);
    EXPECT_EQ(EdmLoadManager::GetInstance().WaitLoadStateChange(), ERR_OK);

    callback.OnLoadSystemAbilityFail(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    EdmLoadManager::GetInstance().InitLoadState();
    EXPECT_FALSE(EdmLoadManager::GetInstance().state_);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
