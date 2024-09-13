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
#include "set_watermark_image_plugin.h"

#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"
#include "iservice_registry.h"
#include "plugin_manager.h"
#include "policy_manager.h"
#include "system_ability_definition.h"
#include "transaction/rs_interfaces.h"
#include "watermark_image_serializer.h"
#include "watermark_application_observer.h"
#include "window_manager.h"
#include "wm_common.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<SetWatermarkImagePlugin>());
const std::string WATERMARK_IMAGE_DIR_PATH = "/data/service/el1/public/edm/watermark/";
const std::string FILE_PREFIX = "edm_";
constexpr int32_t MAX_POLICY_NUM = 100;
SetWatermarkImagePlugin::SetWatermarkImagePlugin()
{
    EDMLOGI("SetWatermarkImagePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::WATERMARK_IMAGE;
    policyName_ = "watermark_image_policy";
    permissionConfig_.permission = "ohos.permission.ENTERPRISE_MANAGE_SECURITY";
    permissionConfig_.permissionType = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode SetWatermarkImagePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("SetWatermarkImagePlugin start");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return SetSingleWatermarkImage(data, reply, policyData);
    } else if (type == FuncOperateType::REMOVE) {
        return CancelWatermarkImage(data, reply, policyData);
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode SetWatermarkImagePlugin::CancelWatermarkImage(MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData)
{
    EDMLOGI("SetWatermarkImagePlugin CancelWatermarkImage start");
    std::string bundleName = data.ReadString();
    int32_t accountId = data.ReadInt32();
    if (bundleName.empty() || accountId <= 0) {
        EDMLOGE("SetWatermarkImagePlugin CancelWatermarkImage param error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData.policyData, currentData);
    auto key = std::make_pair(bundleName, accountId);
    auto it = currentData.find(key);
    if (it != currentData.end()) {
        std::string filePath = WATERMARK_IMAGE_DIR_PATH + it->second.fileName;
        SetProcessWatermark(bundleName, it->second.fileName, accountId, false);
        if (!SetWatermarkToRS(filePath, nullptr)) {
            EDMLOGE("SetWatermarkToRS fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        currentData.erase(key);
        int32_t ret = remove(filePath.c_str());
        if (ret != 0) {
            EDMLOGE("SetWatermarkImagePlugin SetWatermarkImage remove failed");
        }
    }

    if (currentData.empty()) {
        UnsubscribeAppState();
    }
    std::string afterHandle;
    serializer->Serialize(currentData, afterHandle);
    policyData.isChanged = (afterHandle != policyData.policyData);
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    return ERR_OK;
}

void SetWatermarkImagePlugin::SetAllWatermarkImage()
{
    EDMLOGI("SetAllWatermarkImage");
    std::string policyData;
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", "watermark_image_policy", policyData, DEFAULT_USER_ID);

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData, currentData);
    if (currentData.empty()) {
        return;
    }

    for (auto it = currentData.begin(); it != currentData.end(); it++) {
        EDMLOGD("SetAllWatermarkImage fileName=%{public}s", it->second.fileName.c_str());
        auto pixelMap = GetImageFromUrlUint8(it->second);
        if (pixelMap == nullptr) {
            EDMLOGE("SetAllWatermarkImage GetImageFromUrlUint8 null");
            continue;
        }
        if (!SetWatermarkToRS(it->second.fileName, pixelMap)) {
            EDMLOGE("SetWatermarkToRS fail");
            return;
        }
    }
    if (!SubscribeAppState()) {
        EDMLOGE("SetWatermarkImagePlugin SubscribeAppState error");
    }
}

void SetWatermarkImagePlugin::SetProcessWatermarkOnAppStart(const std::string &bundleName,
    int32_t accountId, int32_t pid, bool enabled)
{
    if (bundleName.empty() || accountId <= 0 || pid <= 0) {
        return;
    }

    std::string policyData;
    auto policyManager = IPolicyManager::GetInstance();
    policyManager->GetPolicy("", "watermark_image_policy", policyData, DEFAULT_USER_ID);

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData, currentData);
    std::string fileName = currentData[std::pair<std::string, int32_t>{bundleName, accountId}].fileName;
    if (fileName.empty()) {
        return;
    }
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetProcessWatermark(pid, fileName, enabled);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetAllWatermarkImage SetProcessWatermarkOnAppStart error");
    }
}

ErrCode SetWatermarkImagePlugin::SetSingleWatermarkImage(MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData)
{
    std::string bundleName = data.ReadString();
    auto pixelMap = std::shared_ptr<Media::PixelMap>(data.ReadParcelable<Media::PixelMap>());
    int32_t accountId = data.ReadInt32();
    if (bundleName.empty() || pixelMap == nullptr || accountId <= 0) {
        EDMLOGE("SetWatermarkImagePlugin param error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData.policyData, currentData);
    auto key = std::make_pair(bundleName, accountId);
    std::string oldFileName = currentData[key].fileName;
    std::string fileName = FILE_PREFIX + std::to_string(time(nullptr));
    std::string filePath = WATERMARK_IMAGE_DIR_PATH + fileName;
    currentData[key] = WatermarkImageType{fileName, pixelMap->GetWidth(), pixelMap->GetHeight()};
    if (currentData.size() > MAX_POLICY_NUM) {
        EDMLOGE("SetWatermarkImagePlugin policy max");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (!SetWatermarkToRS(fileName, pixelMap)) {
        EDMLOGE("SetWatermarkToRS fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!SetImageUint8(pixelMap, filePath)) {
        EDMLOGE("SetWatermarkImagePlugin SetImageUint8 error.fileName=%{public}s", fileName.c_str());
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!SubscribeAppState()) {
        EDMLOGE("SetWatermarkImagePlugin SubscribeAppState error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!oldFileName.empty()) {
        std::string oldFilePath = WATERMARK_IMAGE_DIR_PATH + oldFileName;
        int32_t ret = remove(oldFilePath.c_str());
        if (ret != 0) {
            EDMLOGE("SetWatermarkImagePlugin SetWatermarkImage remove failed");
        }
        SetProcessWatermark(bundleName, oldFileName, accountId, false);
    }
    SetProcessWatermark(bundleName, fileName, accountId, true);

    std::string afterHandle;
    serializer->Serialize(currentData, afterHandle);
    policyData.isChanged = (afterHandle != policyData.policyData);
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    return ERR_OK;
}

bool SetWatermarkImagePlugin::SetWatermarkToRS(const std::string &name, std::shared_ptr<Media::PixelMap> watermarkImg)
{
    EDMLOGI("SetWatermarkToRS %{public}s", name.c_str());
    return Rosen::RSInterfaces::GetInstance().SetWatermark(name, watermarkImg);
}

void SetWatermarkImagePlugin::SetProcessWatermark(const std::string &bundleName,
    const std::string &fileName, int32_t accountId, bool enabled)
{
    EDMLOGI("SetProcessWatermark start");
    if (fileName.empty()) {
        return;
    }
    auto appManager = GetAppManager();
    if (appManager == nullptr) {
        EDMLOGE("SetProcessWatermark IAppMgr null.");
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int res = appManager->GetRunningProcessInformation(bundleName, accountId, infos);
    if (res != ERR_OK) {
        EDMLOGE("GetRunningProcessInformation fail!");
        return;
    }
    if (infos.empty() || infos[0].pid_ == 0) {
        EDMLOGD("GetRunning Process Information pid empty");
        return;
    }

    Rosen::WMError ret = Rosen::WindowManager::GetInstance().SetProcessWatermark(infos[0].pid_, fileName, enabled);
    if (ret != Rosen::WMError::WM_OK) {
        EDMLOGE("SetProcessWatermark fail!code: %{public}d", ret);
    }
}

bool SetWatermarkImagePlugin::SetImageUint8(const std::shared_ptr<Media::PixelMap> &pixelMap, const std::string &url)
{
    EDMLOGI("SetImageUint8 start");
    std::ofstream outfile(url, std::ios::binary);
    if (outfile.fail()) {
        EDMLOGE("SetImageUint8 Open file fail!");
        return false;
    }
    int32_t size = pixelMap->GetByteCount();
    if (size <= 0) {
        EDMLOGE("SetImageUint8 size %{public}d", size);
        outfile.close();
        return false;
    }
    uint8_t* pixels = (uint8_t*)malloc(size);
    if (pixels == nullptr) {
        EDMLOGE("SetImageUint8 malloc fail!");
        outfile.close();
        return false;
    }
    uint32_t ret = pixelMap->ReadPixels(size, pixels);
    if (ret != ERR_OK) {
        EDMLOGE("SetImageUint8 ReadPixels fail!");
        outfile.close();
        free(pixels);
        return false;
    }
    outfile.write(reinterpret_cast<char*>(pixels), size);
    outfile.close();
    free(pixels);
    if (chmod(url.c_str(), S_IRUSR | S_IWUSR) != 0) {
        EDMLOGE("SetImageUint8 chmod fail!");
        return false;
    }
    return true;
}

std::shared_ptr<Media::PixelMap> SetWatermarkImagePlugin::GetImageFromUrlUint8(const WatermarkImageType &imageType)
{
    EDMLOGI("GetImageFromUrlUint8 start");
    std::string filePath = WATERMARK_IMAGE_DIR_PATH + imageType.fileName;
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
    uint8_t data[size];
    infile.read(reinterpret_cast<char*>(data), size);
    infile.close();
    Media::InitializationOptions opt;
    opt.size.width = imageType.width;
    opt.size.height = imageType.height;
    opt.editable = true;
    auto pixelMap = Media::PixelMap::Create(opt);
    if (pixelMap == nullptr) {
        EDMLOGE("GetImageFromUrlUint8 Create PixelMap error");
        return nullptr;
    }
    uint32_t ret = pixelMap->WritePixels(data, size);
    if (ret != ERR_OK) {
        EDMLOGE("GetImageFromUrlUint8 WritePixels error");
        return nullptr;
    }
    return pixelMap;
}

bool SetWatermarkImagePlugin::SubscribeAppState()
{
    if (applicationObserver_) {
        EDMLOGD("WatermarkApplicationObserver has subscribed");
        return true;
    }
    applicationObserver_ = new (std::nothrow) WatermarkApplicationObserver(*this);
    auto appManager = GetAppManager();
    if (!applicationObserver_ || !appManager) {
        EDMLOGE("WatermarkApplicationObserver or appmanager null");
        return false;
    }
    if (appManager->RegisterApplicationStateObserver(applicationObserver_)) {
        EDMLOGE("register WatermarkApplicationObserver fail!");
        applicationObserver_.clear();
        applicationObserver_ = nullptr;
        return false;
    }
    return true;
}

bool SetWatermarkImagePlugin::UnsubscribeAppState()
{
    if (!applicationObserver_) {
        EDMLOGD("WatermarkApplicationObserver has unsubscribed");
        return true;
    }
    auto appManager = GetAppManager();
    if (!appManager) {
        EDMLOGE("appManger null");
        return false;
    }
    if (appManager->UnregisterApplicationStateObserver(applicationObserver_)) {
        EDMLOGE("UnregisterApplicationStateObserver fail!");
        return false;
    }
    applicationObserver_.clear();
    applicationObserver_ = nullptr;
    return true;
}

sptr<AppExecFwk::IAppMgr> SetWatermarkImagePlugin::GetAppManager()
{
    auto sysAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sysAbilityMgr == nullptr) {
        EDMLOGE("GetRemoteObjectOfSystemAbility fail.");
        return nullptr;
    }
    auto remoteObject = sysAbilityMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        EDMLOGE("GetSystemAbility fail.");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(remoteObject);
}

ErrCode SetWatermarkImagePlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, int32_t userId)
{
    std::map<std::pair<std::string, int32_t>, WatermarkImageType> currentData;
    auto serializer = WatermarkImageSerializer::GetInstance();
    serializer->Deserialize(policyData, currentData);
    for (auto it = currentData.begin(); it != currentData.end(); ++it) {
        SetProcessWatermark(it->first.first, it->second.fileName, it->first.second, false);
        if (!SetWatermarkToRS(it->second.fileName, nullptr)) {
            EDMLOGE("SetWatermarkToRS fail");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    if (!UnsubscribeAppState()) {
        EDMLOGE("SetWatermarkImagePlugin OnAdminRemove UnsubscribeAppState fail");
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS

