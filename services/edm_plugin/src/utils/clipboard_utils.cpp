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

#include "clipboard_utils.h"

#include "edm_log.h"
#include "pasteboard_client.h"
namespace OHOS {
namespace EDM {
ErrCode ClipboardUtils::HandlePasteboardPolicy(std::map<int32_t, ClipboardPolicy> &data)
{
    EDMLOGI("ClipboardUtils handlePasteboardPolicy.");
    auto plugin_ = MiscServices::PasteboardClient::GetInstance();
    std::map<uint32_t, MiscServices::ShareOption> setMap;
    std::vector<uint32_t> removeVector;
    for (const auto &item : data) {
        switch (item.second) {
            case ClipboardPolicy::DEFAULT:
                removeVector.emplace_back(item.first);
                break;
            case ClipboardPolicy::IN_APP:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::InApp));
                break;
            case ClipboardPolicy::LOCAL_DEVICE:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::LocalDevice));
                break;
            case ClipboardPolicy::CROSS_DEVICE:
                setMap.insert(std::make_pair(item.first, MiscServices::ShareOption::CrossDevice));
                break;
            default:
                break;
        }
    }
    ErrCode setRet = ERR_OK;
    ErrCode rmRet = ERR_OK;
    if (!setMap.empty()) {
        setRet = plugin_->SetGlobalShareOption(setMap);
    }
    if (!removeVector.empty()) {
        rmRet = plugin_->RemoveGlobalShareOption(removeVector);
    }
    if (setRet != ERR_OK || rmRet != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode ClipboardUtils::RemoveAllPasteboardPolicy(std::map<int32_t, ClipboardPolicy> &data)
{
    EDMLOGI("ClipboardUtils removeAllPasteboardPolicy.");
    auto plugin_ = MiscServices::PasteboardClient::GetInstance();
    std::vector<uint32_t> removeVector;
    for (auto it = data.begin(); it != data.end(); it++) {
        removeVector.emplace_back(it->first);
    }
    return plugin_->RemoveGlobalShareOption(removeVector);
}
} // namespace EDM
} // namespace OHOS