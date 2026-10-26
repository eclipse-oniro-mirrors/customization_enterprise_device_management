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

#include "install_plugin_fuzzer.h"

#include <fcntl.h>
#include <system_ability_definition.h>

#include "common_fuzzer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code.h"
#include "ienterprise_device_mgr.h"
#include "message_parcel.h"
#include "utils.h"
#define private public
#include "install_plugin.h"
#undef private

namespace OHOS {
namespace EDM {
constexpr size_t MIN_SIZE = 29;
constexpr size_t STRING_COUNT = 9;
constexpr size_t INT32_COUNT = 5;
constexpr int32_t WITHOUT_USERID = 0;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    TEST::Utils::SetEdmPermissions();
    return 0;
}

static void FuzzIpcInstall(const uint8_t *data, size_t size, int32_t &pos, int32_t stringSize)
{
    uint32_t code = POLICY_FUNC_CODE(static_cast<uint32_t>(FuncOperateType::SET), EdmInterfaceCode::INSTALL);
    AppExecFwk::ElementName admin;
    admin.SetBundleName(CommonFuzzer::GetString(data, pos, stringSize, size));
    admin.SetAbilityName(CommonFuzzer::GetString(data, pos, stringSize, size));
    MessageParcel parcel;
    parcel.WriteInterfaceToken(IEnterpriseDeviceMgrIdl::GetDescriptor());
    parcel.WriteInt32(WITHOUT_USERID);
    parcel.WriteParcelable(&admin);
    std::string path(CommonFuzzer::GetString(data, pos, stringSize, size));
    std::vector<std::string> hapFilePaths = { path };
    parcel.WriteStringVector(hapFilePaths);
    parcel.WriteInt32(0);
    int32_t installParamUserId = CommonFuzzer::GetU32Data(data, pos, size);
    parcel.WriteInt32(installParamUserId);
    int32_t installParamInstallFlag = CommonFuzzer::GetU32Data(data, pos, size);
    parcel.WriteInt32(installParamInstallFlag);
    std::vector<std::string> keys;
    std::vector<std::string> values;
    parcel.WriteStringVector(keys);
    parcel.WriteStringVector(values);
    CommonFuzzer::OnRemoteRequestFuzzerTest(code, data, size, parcel);
}

static void FuzzPluginMethods(const uint8_t *data, size_t size, int32_t &pos, int32_t stringSize)
{
    InstallPlugin plugin;
    plugin.CreateDirectory();

    std::vector<std::string> files = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    plugin.DeleteFiles(files);

    int32_t resultCode = CommonFuzzer::GetU32Data(data);
    std::string errorMessage = CommonFuzzer::GetString(data, pos, stringSize, size);
    MessageParcel resultReply;
    std::vector<std::string> resultRealPaths = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    plugin.HandleInstallResult(resultCode, errorMessage, resultReply, resultRealPaths);

    std::string hapFilePath = CommonFuzzer::GetString(data, pos, stringSize, size);
    std::string parsedBundleName;
    InstalledBundleType bundleType = InstalledBundleType::NORMAL;
    plugin.GetBundleInfoAndType(hapFilePath, parsedBundleName, bundleType);

    std::string copyTempPath;
    MessageParcel copyReply;
    std::string copyHapFilePath = CommonFuzzer::GetString(data, pos, stringSize, size);
    plugin.CopyHapFile(-1, copyHapFilePath, copyTempPath, copyReply);

    MessageParcel contentReply;
    plugin.CopyFileContent(-1, -1, contentReply);

    InstallParam streamParam;
    streamParam.userId = CommonFuzzer::GetU32Data(data, pos, size);
    streamParam.installFlag = CommonFuzzer::GetU32Data(data, pos, size);
    std::vector<std::string> streamPaths = { CommonFuzzer::GetString(data, pos, stringSize, size) };
    MessageParcel streamReply;
    plugin.ExecuteStreamInstall(streamPaths, streamParam, streamReply);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < MIN_SIZE) {
        return 0;
    }
    int32_t pos = 0;
    int32_t stringSize = (size - sizeof(int32_t) * INT32_COUNT) / STRING_COUNT;
    FuzzIpcInstall(data, size, pos, stringSize);
    FuzzPluginMethods(data, size, pos, stringSize);
    return 0;
}
} // namespace EDM
} // namespace OHOS
