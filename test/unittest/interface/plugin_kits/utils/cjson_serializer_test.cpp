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

#include "cjson_serializer.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string TEST_POLICY_DATA = "{\"test_app_id\": \"{\\\"test_policy_name\\\":\\\"test_policy_value\\\"}\"}";
class CjsonSerializerTest : public testing::Test {};
/**
 * @tc.name: TestWritePolicy
 * @tc.desc: Test CjsonSerializer::WritePolicy func.
 * and policies is empty.
 * @tc.type: FUNC
 */
HWTEST_F(CjsonSerializerTest, TestWritePolicy, TestSize.Level1)
{
    auto serializer =  CjsonSerializer::GetInstance();
    cJSON* jsonPolicy;
    MessageParcel reply;
    serializer->Deserialize(TEST_POLICY_DATA, jsonPolicy);
    ASSERT_TRUE(serializer->WritePolicy(reply, jsonPolicy));

    cJSON* jsonPolicy2; 
    std::string strPolicy;
    ASSERT_TRUE(serializer->GetPolicy(reply, jsonPolicy2));
    ASSERT_TRUE(serializer->Serialize(jsonPolicy2, strPolicy));

    std::string jsonString = "";
    cJSON* root = cJSON_Parse(TEST_POLICY_DATA.c_str());
    char* cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        jsonString = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);

    ASSERT_TRUE(jsonString == strPolicy);

    std::vector<cJSON*> jsons{jsonPolicy};
    ASSERT_TRUE(serializer->MergePolicy(jsons, jsonPolicy2));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
