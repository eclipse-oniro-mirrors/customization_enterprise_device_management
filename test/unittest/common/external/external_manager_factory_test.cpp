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

#include "external_manager_factory.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class ExternalManagerFactoryTest : public testing::Test {};
/**
 * @tc.name: TestCreateAppManager
 * @tc.desc: Test CreateAppManager function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalManagerFactoryTest, TestCreateAppManager, TestSize.Level1)
{
    ExternalManagerFactory externalManagerFactory;
    ASSERT_TRUE(externalManagerFactory.CreateAppManager() != nullptr);
}

/**
 * @tc.name: TestCreateBundleManager
 * @tc.desc: Test CreateBundleManager function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalManagerFactoryTest, TestCreateBundleManager, TestSize.Level1)
{
    ExternalManagerFactory externalManagerFactory;
    ASSERT_TRUE(externalManagerFactory.CreateBundleManager() != nullptr);
}

/**
 * @tc.name: TestCreateOsAccountManager
 * @tc.desc: Test CreateOsAccountManager function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalManagerFactoryTest, TestCreateOsAccountManager, TestSize.Level1)
{
    ExternalManagerFactory externalManagerFactory;
    ASSERT_TRUE(externalManagerFactory.CreateOsAccountManager() != nullptr);
}

/**
 * @tc.name: TestCreateAccessTokenManager
 * @tc.desc: Test CreateAccessTokenManager function.
 * @tc.type: FUNC
 */
HWTEST_F(ExternalManagerFactoryTest, TestCreateAccessTokenManager, TestSize.Level1)
{
    ExternalManagerFactory externalManagerFactory;
    ASSERT_TRUE(externalManagerFactory.CreateAccessTokenManager() != nullptr);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS