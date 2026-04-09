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

#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
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

SetScreenWatermarkImagePlugin::SetScreenWatermarkImagePlugin()
{
    EDMLOGI("SetScreenWatermarkImagePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SCREEN_WATERMARK_IMAGE;
    policyName_ = PolicyName::POLICY_SCREEN_WATERMARK_IMAGE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

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

ErrCode SetScreenWatermarkImagePlugin::SetPolicy(MessageParcel &data,
    WatermarkImageType &currentData, WatermarkImageType &mergeData)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::SetPolicy start");
    WatermarkParam param;
    if (!GetWatermarkParam(param, data)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy GetWatermarkParam failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto pixelMap =
        CreatePixelMapFromUint8(reinterpret_cast<const uint8_t *>(param.pixels), param.size, param.width, param.height);
    if (pixelMap == nullptr) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy CreatePixelMapFromUint8 failed");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string fileName = FILE_PREFIX + std::to_string(time(nullptr));
    std::string filePath = SCREEN_WATERMARK_DIR_PATH + fileName;
    if (!SetImageUint8(param.pixels, param.size, filePath)) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetPolicy SetImageUint8 failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetScreenWatermarkImage(pixelMap, 1);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetScreenWatermarkImagePlugin SetScreenWatermarkImage fail!code: %{public}d", ret);
        RemoveImageFile(fileName);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!currentData.fileName.empty()) {
        RemoveImageFile(currentData.fileName);
    }
    WatermarkImageType afterHandle{fileName, param.width, param.height};
    currentData = afterHandle;
    mergeData = afterHandle;
    EDMLOGI("SetScreenWatermarkImagePlugin::SetPolicy success, fileName=%{public}s", fileName.c_str());
    return ERR_OK;
}

ErrCode SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage(WatermarkImageType &currentData)
{
    EDMLOGI("SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage start");
    if (currentData.fileName.empty()) {
        EDMLOGI("SetScreenWatermarkImagePlugin::CancelScreenWatermarkImage current admin dont have policy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
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
    
    // 删除图片文件
    if (!currentData.fileName.empty()) {
        RemoveImageFile(currentData.fileName);
    }
    
    EDMLOGI("SetScreenWatermarkImagePlugin::OnAdminRemove success");
    return ERR_OK;
}

ErrCode SetScreenWatermarkImagePlugin::GetOthersMergePolicyData(const std::string &adminName,
    int32_t userId, std::string &othersMergePolicyData)
{
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", PolicyName::POLICY_SCREEN_WATERMARK_IMAGE,
        othersMergePolicyData, EdmConstants::DEFAULT_USER_ID);
    return ERR_OK;
}

bool SetScreenWatermarkImagePlugin::GetWatermarkParam(WatermarkParam &param, MessageParcel &data)
{
    param.width = data.ReadInt32();
    param.height = data.ReadInt32();
    param.size = data.ReadInt32();
    if (param.size <= 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::GetWatermarkParam size error");
        return false;
    }
    param.SetPixels(const_cast<void*>(data.ReadRawData(param.size)));
    if (param.pixels == nullptr) {
        EDMLOGE("GetWatermarkParam pixels error");
        return false;
    }
    return true;
}

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
    outfile.write(reinterpret_cast<const char *>(pixels), static_cast<std::streamsize>(size));
    outfile.close();
    if (chmod(url.c_str(), S_IRUSR | S_IWUSR) != 0) {
        EDMLOGE("SetScreenWatermarkImagePlugin::SetImageUint8 chmod fail!");
        return false;
    }
    return true;
}

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
    if (size <= 0) {
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
} // namespace EDM
} // namespace OHOS
