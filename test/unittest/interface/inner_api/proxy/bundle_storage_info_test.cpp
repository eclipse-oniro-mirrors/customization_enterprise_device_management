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

#include "bundle_storage_info.h"
#include "edm_constants.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::EDM;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t TEST_APP_SIZE = 1024;
const int32_t TEST_DATA_SIZE = 2048;
class BundleStorageInfoTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: BundleStorageInfoMarshalling001
 * @tc.desc: Test BundleStorageInfo Marshalling success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling001, TestSize.Level1)
{
    BundleStorageInfo info;
    info.bundleName = "com.test.app";
    info.appSize = TEST_APP_SIZE;
    info.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = info.Marshalling(parcel);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: BundleStorageInfoReadFromParcel001
 * @tc.desc: Test BundleStorageInfo ReadFromParcel success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadFromParcel001, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    ASSERT_TRUE(ret);
    ASSERT_EQ(readInfo.bundleName, "com.test.app");
    ASSERT_EQ(readInfo.appSize, TEST_APP_SIZE);
    ASSERT_EQ(readInfo.dataSize, TEST_DATA_SIZE);
}

/**
 * @tc.name: BundleStorageInfoMarshalling002
 * @tc.desc: Test BundleStorageInfo Marshalling with large values
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling002, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.large.app";
    writeInfo.appSize = INT64_MAX;
    writeInfo.dataSize = INT64_MAX;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    ASSERT_TRUE(ret);
    ASSERT_EQ(readInfo.bundleName, "com.test.large.app");
    ASSERT_EQ(readInfo.appSize, INT64_MAX);
    ASSERT_EQ(readInfo.dataSize, INT64_MAX);
}

/**
 * @tc.name: BundleStorageInfoMarshalling003
 * @tc.desc: Test BundleStorageInfo Marshalling with negative values
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling003, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.negative.app";
    writeInfo.appSize = -1;
    writeInfo.dataSize = -1;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    ASSERT_TRUE(ret);
    ASSERT_EQ(readInfo.bundleName, "com.test.negative.app");
    ASSERT_EQ(readInfo.appSize, -1);
    ASSERT_EQ(readInfo.dataSize, -1);
}

/**
 * @tc.name: BundleStorageInfoMarshalling004
 * @tc.desc: Test BundleStorageInfo Marshalling with unicode bundleName
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoMarshalling004, TestSize.Level1)
{
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;

    MessageParcel parcel;
    bool ret = writeInfo.Marshalling(parcel);
    ASSERT_TRUE(ret);

    BundleStorageInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    ASSERT_TRUE(ret);
    ASSERT_EQ(readInfo.bundleName, "com.test.app");
    ASSERT_EQ(readInfo.appSize, TEST_APP_SIZE);
    ASSERT_EQ(readInfo.dataSize, TEST_DATA_SIZE);
}

/**
 * @tc.name: BundleStorageInfoReadVectorSuccess001
 * @tc.desc: Test BundleStorageInfo::ReadBundleStorageInfoVector success
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadVectorSuccess001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint32(1);
    
    BundleStorageInfo writeInfo;
    writeInfo.bundleName = "com.test.app";
    writeInfo.appSize = TEST_APP_SIZE;
    writeInfo.dataSize = TEST_DATA_SIZE;
    writeInfo.Marshalling(parcel);
    
    std::vector<BundleStorageInfo> result;
    bool ret = BundleStorageInfo::ReadBundleStorageInfoVector(parcel, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].bundleName, "com.test.app");
    ASSERT_EQ(result[0].appSize, TEST_APP_SIZE);
    ASSERT_EQ(result[0].dataSize, TEST_DATA_SIZE);
}

/**
 * @tc.name: BundleStorageInfoReadVectorMultiple001
 * @tc.desc: Test BundleStorageInfo::ReadBundleStorageInfoVector with multiple items
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadVectorMultiple001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint32(3);
    
    for (int i = 1; i <= 3; i++) {
        BundleStorageInfo info;
        info.bundleName = "com.test.app" + std::to_string(i);
        info.appSize = TEST_APP_SIZE * i;
        info.dataSize = TEST_DATA_SIZE * i;
        info.Marshalling(parcel);
    }
    
    std::vector<BundleStorageInfo> result;
    bool ret = BundleStorageInfo::ReadBundleStorageInfoVector(parcel, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 3);
    ASSERT_EQ(result[1].bundleName, "com.test.app2");
    ASSERT_EQ(result[1].appSize, TEST_APP_SIZE * 2);
}

/**
 * @tc.name: BundleStorageInfoReadVectorEmpty001
 * @tc.desc: Test BundleStorageInfo::ReadBundleStorageInfoVector with empty vector
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadVectorEmpty001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint32(0);
    
    std::vector<BundleStorageInfo> result;
    bool ret = BundleStorageInfo::ReadBundleStorageInfoVector(parcel, result);
    ASSERT_TRUE(ret);
    ASSERT_EQ(result.size(), 0);
}

/**
 * @tc.name: BundleStorageInfoReadVectorOverMax001
 * @tc.desc: Test BundleStorageInfo::ReadBundleStorageInfoVector with over max size
 * @tc.type: FUNC
 */
HWTEST_F(BundleStorageInfoTest, BundleStorageInfoReadVectorOverMax001, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteUint32(EdmConstants::POLICIES_MAX_SIZE + 1);
    
    std::vector<BundleStorageInfo> result;
    bool ret = BundleStorageInfo::ReadBundleStorageInfoVector(parcel, result);
    ASSERT_FALSE(ret);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
