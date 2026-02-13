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

#include "notification_manager.h"

#include "media_errors.h"
#include "image_source.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "want_agent_helper.h"

#include "edm_log.h"
#include "edm_constants.h"
#include "language_manager.h"

namespace OHOS {
namespace EDM {
bool NotificationManager::SendSystemNotification(const NotificationInfo &notificationInfo, const IconInfo &iconInfo,
    const WantAgentInfo &wantAgentInfo)
{
    auto notificationContent = CreateNotificationNormalContent(notificationInfo);
    Notification::NotificationRequest request;
    request.SetCreatorUid(EdmConstants::EDM_UID);
    request.SetNotificationControlFlags(Notification::NotificationConstant::ReminderFlag::SA_SELF_BANNER_FLAG);
    request.SetContent(notificationContent);
    // 设置通知图标
    auto pixelMap = GetIconPixelMap(iconInfo);
    if (pixelMap) {
        request.SetLittleIcon(std::move(pixelMap));
    }
    // 设置点击跳转uri
    auto wantAgent = GetWantAgent(wantAgentInfo);
    if (wantAgent) {
        request.SetWantAgent(wantAgent);
    }
    ErrCode res = Notification::NotificationHelper::PublishNotification(request);
    if (FAILED(res)) {
        EDMLOGE("NotificationManager::SendSystemNotification failed, %{public}d", res);
        return false;
    }
    return true;
}

std::shared_ptr<Notification::NotificationContent> NotificationManager::CreateNotificationNormalContent(
    const NotificationInfo &notificationInfo)
{
    auto normalContent = std::make_shared<Notification::NotificationNormalContent>();
    if (normalContent == nullptr) {
        EDMLOGE("NotificationManager::CreateNotificationNormalContent failed.");
        return nullptr;
    }
    normalContent->SetTitle(LanguageManager::GetSystemStringByName(notificationInfo.title));
    normalContent->SetText(LanguageManager::GetSystemStringByName(notificationInfo.body));
    return std::make_shared<Notification::NotificationContent>(normalContent);
}

std::unique_ptr<Media::PixelMap>NotificationManager::GetIconPixelMap(const IconInfo &iconInfo)
{
    if (iconInfo.icon.empty()) {
        EDMLOGE("NotificationManager::GetIconPixelMap icon is empty.");
        return nullptr;
    }
    uint32_t errCode = Media::COMMON_ERR_INVALID_PARAMETER;
    Media::SourceOptions opts;
    auto imageSource = Media::ImageSource::CreateImageSource(iconInfo.icon.c_str(), opts, errCode);
    if (imageSource == nullptr) {
        EDMLOGE("NotificationManager::GetIconPixelMap CreateImageSource failed, %{public}u.", errCode);
        return nullptr;
    }
    Media::DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    if (pixelMap == nullptr) {
        EDMLOGE("NotificationManager::GetIconPixelMap CreatePixelMap failed, %{public}u.", errCode);
        return nullptr;
    }
    pixelMap->scale(iconInfo.xAxis, iconInfo.yAxis);
    return pixelMap;
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>  NotificationManager::GetWantAgent(
    const WantAgentInfo &wantAgentInfo)
{
    if (wantAgentInfo.bundleName.empty() || wantAgentInfo.abilityName.empty()) {
        EDMLOGW("NotificationManager::GetWantAgent bundleName or abilityName is empty.");
        return nullptr;
    }
    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName(wantAgentInfo.bundleName, wantAgentInfo.abilityName);
    want->SetUri(wantAgentInfo.uri);
    std::vector<std::shared_ptr<AAFwk::Want>> wants = {want};
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags = {
        AbilityRuntime::WantAgent::WantAgentConstant::Flags::CONSTANT_FLAG };
    AbilityRuntime::WantAgent::WantAgentInfo wantAgent(0,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY, flags, wants, nullptr);
    return AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgent);
}
} // namespace EDM
} // namespace OHOS
