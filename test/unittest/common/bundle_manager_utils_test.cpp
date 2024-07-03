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

#include "bundle_manager_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
class BundleManagerUtilsTest : public testing::Test {};
/**
 * @tc.name: TestGetAppIdByCallingUid
 * @tc.desc: Test GetAppIdByCallingUid function.
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerUtilsTest, TestGetAppIdByCallingUid, TestSize.Level1)
{
    std::string appId;
    BundleManagerUtils::GetAppIdByCallingUid(appId);
    ASSERT_TRUE(appId.empty());
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS