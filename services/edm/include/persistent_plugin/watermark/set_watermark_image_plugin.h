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

#ifndef SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN__SET_WATERMARK_IMAGE_PLUGIN_H
#define SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN__SET_WATERMARK_IMAGE_PLUGIN_H

#include "app_mgr_interface.h"
#include "iplugin.h"
#include "pixel_map.h"
#include "watermark_image_type.h"
#include "watermark_param.h"

namespace OHOS {
namespace EDM {
class SetWatermarkImagePlugin : public IPlugin {
public:
    SetWatermarkImagePlugin();

    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override;

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {};

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData, const std::string &mergeData,
        int32_t userId) override;

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData, int32_t userId) override {
    };

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override
    {
        return ERR_OK;
    };

    ErrCode GetOthersMergePolicyData(const std::string &adminName, std::string &othersMergePolicyData) override;

    void SetAllWatermarkImage();
    void SetProcessWatermarkOnAppStart(const std::string &bundleName, int32_t accountId, int32_t pid, bool enabled);

private:
    ErrCode SetPolicy(MessageParcel &data, std::map<std::pair<std::string, int32_t>, WatermarkImageType> &currentData,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &mergeData);
    ErrCode CancelWatermarkImage(MessageParcel &data,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &currentData,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &mergeData);
    ErrCode SetSingleWatermarkImage(WatermarkParam &param,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &currentData,
        std::map<std::pair<std::string, int32_t>, WatermarkImageType> &mergeData);
    bool GetWatermarkParam(WatermarkParam &param, MessageParcel &data);
    bool SetWatermarkToRS(const std::string &name, std::shared_ptr<Media::PixelMap> watermarkImg);
    void SetProcessWatermark(const std::string &bundleName, const std::string &fileName, int32_t accountId,
        bool enabled);
    bool SetImageUint8(const void *pixels, int32_t size, const std::string &url);
    std::shared_ptr<Media::PixelMap> GetImageFromUrlUint8(const WatermarkImageType &imageType);
    std::shared_ptr<Media::PixelMap> CreatePixelMapFromUint8(const uint8_t *data, size_t size, int32_t width,
        int32_t height);
    bool SubscribeAppState();
    bool UnsubscribeAppState();
    sptr<AppExecFwk::IAppMgr> GetAppManager();
    sptr<AppExecFwk::IApplicationStateObserver> applicationObserver_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_PERSISTENT_PLUGIN__SET_WATERMARK_IMAGE_PLUGIN_H
