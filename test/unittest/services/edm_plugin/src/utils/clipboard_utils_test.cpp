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

#include "clipboard_utils_test.h"
#include "utils.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
void ClipboardUtilsTest::SetUpTestSuite(void)
{
    Utils::SetEdmInitialEnv();
}

void ClipboardUtilsTest::TearDownTestSuite(void)
{
    Utils::ResetTokenTypeAndUid();
    ASSERT_TRUE(Utils::IsOriginalUTEnv());
    std::cout << "now ut process is orignal ut env : " << Utils::IsOriginalUTEnv() << std::endl;
}

/**
 * @tc.name: HandlePasteboardPolicy
 * @tc.desc: Test ClipboardUtils::HandlePasteboardPolicy when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardUtilsTest, TestHandlePasteboardPolicy, TestSize.Level1)
{
    std::map<int32_t, ClipboardPolicy> result;
    result.insert(std::make_pair(1, ClipboardPolicy::DEFAULT));
    result.insert(std::make_pair(2, ClipboardPolicy::IN_APP));
    result.insert(std::make_pair(3, ClipboardPolicy::LOCAL_DEVICE));
    result.insert(std::make_pair(4, ClipboardPolicy::CROSS_DEVICE));
    ErrCode ret = ClipboardUtils::HandlePasteboardPolicy(result);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveAllPasteboardPolicy
 * @tc.desc: Test ClipboardUtils::RemoveAllPasteboardPolicy when jsonString is empty
 * @tc.type: FUNC
 */
HWTEST_F(ClipboardUtilsTest, TestRemoveAllPasteboardPolicy, TestSize.Level1)
{
    std::map<int32_t, ClipboardPolicy> result;
    result.insert(std::make_pair(1, ClipboardPolicy::DEFAULT));
    result.insert(std::make_pair(2, ClipboardPolicy::IN_APP));
    result.insert(std::make_pair(3, ClipboardPolicy::LOCAL_DEVICE));
    result.insert(std::make_pair(4, ClipboardPolicy::CROSS_DEVICE));
    ErrCode ret = ClipboardUtils::RemoveAllPasteboardPolicy(result);
    ASSERT_TRUE(ret == ERR_OK);
}

} // namespace TEST
} // namespace EDM
} // namespace OHOS