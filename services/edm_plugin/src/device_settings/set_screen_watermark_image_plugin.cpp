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

#include "set_screen_watermark_image_plugin.h"

#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <random>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "display.h"
#include "display_manager.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "ipolicy_manager.h"
#include "iplugin_manager.h"
#include "screen_watermark_image_serializer.h"
#include "window_manager.h"
#include "wm_common.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetScreenWatermarkImagePlugin>());
const std::string SCREEN_WATERMARK_DIR_PATH = "/data/service/el1/public/edm/watermark/";
const std::string FILE_PREFIX = "edm_screen_";
constexpr int32_t RANDOM_NUM_MAX = 9999;
constexpr int32_t WATERMARK_DISPLAY_MODE = 1;
constexpr int32_t IMAGE_SIZE_MULTIPLIER = 2;
constexpr int32_t MAX_IMAGE_SIZE = 128 * 1024 * 1024;

SetScreenWatermarkImagePlugin::SetScreenWatermarkImagePlugin()
{
    EDMLOGI("SetScreenWatermarkImagePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SCREEN_WATERMARK_IMAGE;
    policyName_ = PolicyName::POLICY_SCREEN_WATERMARK_IMAGE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
    this->SetPluginUnloadFlag(false); // 此处是为了避免dlclose对应so出现的稳定性问题，如果dlclose无问题可以删除。
}

// LCOV_EXCL_START
ErrCode SetScreenWatermarkImagePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    
    WatermarkImageType currentData;
    WatermarkImageType mergeData;
    auto serializer = ScreenWatermarkImageSerializer::GetInstance();
    if (!serializer->Deserialize(policyData.policyData, currentData) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergeData)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnHandlePolicy Deserialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (type != FuncOperateType::SET && type != FuncOperateType::REMOVE) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = EdmReturnErrCode::SYSTEM_ABNORMALLY;
    if (type == FuncOperateType::SET) {
        ret = SetPolicy(data, currentData, mergeData);
    } else if (type == FuncOperateType::REMOVE) {
        ret = CancelScreenWatermarkImage(currentData);
    }
    if (FAILED(ret)) {
        return ret;
    }
    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(currentData, afterHandle) || !serializer->Serialize(mergeData, afterMerge)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnHandlePolicy Serialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = (afterHandle != policyData.policyData);
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetScreenWatermarkImagePlugin::SetPolicy(MessageParcel &data,
    WatermarkImageType &currentData, WatermarkImageType &mergeData)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::SetPolicy start");
    WatermarkParam param;
    if (!GetWatermarkParam(param, data)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy GetWatermarkParam failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    auto pixelMap =
        CreatePixelMapFromUint8(reinterpret_cast<const uint8_t *>(param.pixels), param.size, param.width, param.height);
    if (pixelMap == nullptr) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy CreatePixelMapFromUint8 failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (!currentData.fileName.empty()) {
        RemoveImageFile(currentData.fileName);
    }
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, RANDOM_NUM_MAX);
    std::string fileName = FILE_PREFIX + std::to_string(timestamp) + "_" + std::to_string(dis(gen));
    std::string filePath = SCREEN_WATERMARK_DIR_PATH + fileName;
    if (!SetImageUint8(param.pixels, param.size, filePath)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy SetImageUint8 failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetScreenWatermarkImage(pixelMap, WATERMARK_DISPLAY_MODE);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetScreenWatermarkImagePlugin SetScreenWatermarkImage fail!code: %{public}d", ret);
        RemoveImageFile(fileName);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    WatermarkImageType afterHandle{fileName, param.width, param.height};
    currentData = afterHandle;
    mergeData = afterHandle;
    EDMLOGI("SetScreenWatermarkImagePlugin::SetPolicy success, fileName=%{public}s", fileName.c_str());
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage(WatermarkImageType &currentData)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage start");
    if (currentData.fileName.empty()) {
        EDMLOGI("SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage current admin dont have policy");
        return ERR_OK;
    }
    auto pixelMap = GetImageFromUrlUint8(currentData);
    if (pixelMap == nullptr) {
        EDMLOGI("SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage GetImageFromUrlUint8 fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().CleanScreenWatermarkImage(pixelMap);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetScreenWatermarkImagePlugin CleanScreenWatermarkImage fail!code: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    RemoveImageFile(currentData.fileName);
    WatermarkImageType emptyType;
    currentData = emptyType;
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode SetScreenWatermarkImagePlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, const std::string &mergeData, int32_t userId)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::OnAdminRemove start");
    
    WatermarkImageType currentData;
    auto serializer = ScreenWatermarkImageSerializer::GetInstance();
    if (!serializer->Deserialize(policyData, currentData)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnAdminRemove Deserialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return CancelScreenWatermarkImage(currentData);
}

ErrCode SetScreenWatermarkImagePlugin::GetOthersMergePolicyData(const std::string &adminName,
    int32_t userId, std::string &othersMergePolicyData)
{
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", PolicyName::POLICY_SCREEN_WATERMARK_IMAGE,
        othersMergePolicyData, EdmConstants::DEFAULT_USER_ID);
    return ERR_OK;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool SetScreenWatermarkImagePlugin::GetWatermarkParam(WatermarkParam &param, MessageParcel &data)
{
    param.width = data.ReadInt32();
    param.height = data.ReadInt32();
    param.size = data.ReadInt32();
    if (param.size <= 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam size error");
        return false;
    }
    if (param.width <= 0 || param.height <= 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam width or height error");
        return false;
    }
    OHOS::sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (defaultDisplay == nullptr) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam GetDefaultDisplay failed");
        return false;
    }
    int32_t deviceWidth = defaultDisplay->GetWidth();
    int32_t deviceHeight = defaultDisplay->GetHeight();
    if (deviceWidth <= 0 || deviceHeight <= 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam invalid device size, "
                "deviceWidth=%{public}d, deviceHeight=%{public}d", deviceWidth, deviceHeight);
        return false;
    }
    if (param.width > deviceWidth * IMAGE_SIZE_MULTIPLIER || param.height > deviceHeight * IMAGE_SIZE_MULTIPLIER) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam image size exceeds device limit, "
                "imageWidth=%{public}d, imageHeight=%{public}d, deviceWidth=%{public}d, deviceHeight=%{public}d",
                param.width, param.height, deviceWidth, deviceHeight);
        return false;
    }
    param.SetPixels(const_cast<void*>(data.ReadRawData(param.size)));
    if (param.pixels == nullptr) {
        EDMLOGE("GetWatermarkParam pixels error");
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool SetScreenWatermarkImagePlugin::SetImageUint8(const void *pixels, int32_t size, const std::string &url)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::SetImageUint8 start, url=%{public}s", url.c_str());
    // 创建目录
    std::string dirPath = SCREEN_WATERMARK_DIR_PATH;
    if (access(dirPath.c_str(), F_OK) != 0) {
        if (mkdir(dirPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
            EDMLOGE("SetScreenWatermarkImagePlugin::SetImageUint8 mkdir failed");
            return false;
        }
    }
    std::ofstream outfile(url, std::ios::binary);
    if (outfile.fail()) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetImageUint8 Open file fail!");
        return false;
    }
    if (!outfile.write(reinterpret_cast<const char *>(pixels), static_cast<std::streamsize>(size))) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetImageUint8 write failed");
        outfile.close();
        remove(url.c_str());
        return false;
    }
    outfile.close();
    if (chmod(url.c_str(), S_IRUSR | S_IWUSR) != 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetImageUint8 chmod fail!");
        remove(url.c_str());
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
bool SetScreenWatermarkImagePlugin::RemoveImageFile(const std::string &fileName)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::RemoveImageFile start, fileName=%{public}s", fileName.c_str());
    if (fileName.empty()) {
        EDMLOGW("SetScreenWatermarkImagePlugin::RemoveImageFile fileName is empty");
        return true;
    }
    std::string filePath = SCREEN_WATERMARK_DIR_PATH + fileName;
    int32_t ret = remove(filePath.c_str());
    if (ret != 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::RemoveImageFile remove failed, ret=%{public}d", ret);
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
std::shared_ptr<Media::PixelMap> SetScreenWatermarkImagePlugin::GetImageFromUrlUint8(
    const WatermarkImageType &imageType)
{
    EDMLOGI("GetImageFromUrlUint8 start");
    std::string filePath = SCREEN_WATERMARK_DIR_PATH + imageType.fileName;
    std::ifstream infile(filePath, std::ios::binary | std::ios::ate);
    if (infile.fail()) {
        EDMLOGE("Open file fail! fileName=%{public}s", imageType.fileName.c_str());
        return nullptr;
    }
    std::streamsize size = infile.tellg();
    if (size <= 0 || size > MAX_IMAGE_SIZE) {
        EDMLOGE("GetImageFromUrlUint8 size %{public}d", (int32_t)size);
        infile.close();
        return nullptr;
    }
    infile.seekg(0, std::ios::beg);
    uint8_t* data = (uint8_t*) malloc(size);
    if (data == nullptr) {
        EDMLOGE("GetImageFromUrlUint8 malloc fail");
        infile.close();
        return nullptr;
    }
    infile.read(reinterpret_cast<char *>(data), size);
    infile.close();
    auto pixelMap = CreatePixelMapFromUint8(data, size, imageType.width, imageType.height);
    free(data);
    return pixelMap;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
std::shared_ptr<Media::PixelMap> SetScreenWatermarkImagePlugin::CreatePixelMapFromUint8(
    const uint8_t *data, size_t size, int32_t width, int32_t height)
{
    Media::InitializationOptions opt;
    opt.size.width = width;
    opt.size.height = height;
    opt.editable = true;
    auto pixelMap = Media::PixelMap::Create(opt);
    if (pixelMap == nullptr) {
        EDMLOGE("CreatePixelMapFromUint8 Create PixelMap error");
        return nullptr;
    }
    uint32_t ret = pixelMap->WritePixels(data, size);
    if (ret != ERR_OK) {
        EDMLOGE("CreatePixelMapFromUint8 WritePixels error");
        return nullptr;
    }
    return pixelMap;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
void SetScreenWatermarkImagePlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::OnOtherServiceStart");
    std::string policyData;
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", PolicyName::POLICY_SCREEN_WATERMARK_IMAGE, policyData,
        EdmConstants::DEFAULT_USER_ID);
    if (policyData.empty()) {
        return;
    }
    WatermarkImageType currentData;
    auto serializer = ScreenWatermarkImageSerializer::GetInstance();
    if (!serializer->Deserialize(policyData, currentData)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnOtherServiceStart Deserialize failed");
        return;
    }
    if (currentData.fileName.empty()) {
        return;
    }
    auto pixelMap = GetImageFromUrlUint8(currentData);
    if (pixelMap == nullptr) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnOtherServiceStart GetImageFromUrlUint8 failed");
        return;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetScreenWatermarkImage(pixelMap, WATERMARK_DISPLAY_MODE);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetScreenWatermarkImagePlugin::OnOtherServiceStart SetScreenWatermarkImage failed, code: %{public}d",
            ret);
    }
}
// LCOV_EXCL_STOP
} // namespace EDM
} // namespace OHOS
