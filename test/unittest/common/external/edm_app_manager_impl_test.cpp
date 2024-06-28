/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "application_state_observer.h"
#include "edm_app_manager_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class EdmAppManagerImplTest : public testing::Test {};


/**
 * @tc.name: TestRegisterApplicationStateObserver
 * @tc.desc: Test RegisterApplicationStateObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppManagerImplTest, TestRegisterApplicationStateObserver, TestSize.Level1)
{
    EdmAppManagerImpl edmAppManagerImpl;
    int ret = edmAppManagerImpl.RegisterApplicationStateObserver(nullptr);
    ASSERT_TRUE(ret == ERR_APPLICATION_SERVICE_ABNORMALLY);
}

/**
 * @tc.name: TestUnregisterApplicationStateObserver
 * @tc.desc: Test UnregisterApplicationStateObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppManagerImplTest, TestUnregisterApplicationStateObserver, TestSize.Level1)
{
    EdmAppManagerImpl edmAppManagerImpl;
    int ret = edmAppManagerImpl.UnregisterApplicationStateObserver(nullptr);
    ASSERT_TRUE(ret == ERR_APPLICATION_SERVICE_ABNORMALLY);
}

/**
 * @tc.name: TestRegisterApplicationStateObserver02
 * @tc.desc: Test UnregisterApplicationStateObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(EdmAppManagerImplTest, TestRegisterApplicationStateObserver02, TestSize.Level1)
{
    EdmAppManagerImpl edmAppManagerImpl;
    sptr<AppExecFwk::IApplicationStateObserver> appStateObserver;
    int ret = edmAppManagerImpl.RegisterApplicationStateObserver(appStateObserver);
    ASSERT_TRUE(ret == ERR_APPLICATION_SERVICE_ABNORMALLY);
    
    ret = edmAppManagerImpl.UnregisterApplicationStateObserver(appStateObserver);
    ASSERT_TRUE(ret == ERR_APPLICATION_SERVICE_ABNORMALLY);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
