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

#include "get_all_main_window_states_plugin.h"

#include <map>

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "session_manager_lite.h"
#include "window_manager_lite.h"

namespace OHOS {
namespace EDM {
// LCOV_EXCL_START
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<GetAllMainWindowStatesPlugin>());

GetAllMainWindowStatesPlugin::GetAllMainWindowStatesPlugin()
{
    policyCode_ = EdmInterfaceCode::GET_ALL_MAIN_WINDOW_STATES;
    policyName_ = PolicyName::POLICY_GET_ALL_MAIN_WINDOW_STATES;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetAllMainWindowStatesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetAllMainWindowStatesPlugin OnGetPolicy");
    std::vector<MainWindowStates> mainWindowStates;
    ErrCode ret = QueryMainWindowStates(userId, mainWindowStates);
    if (FAILED(ret)) {
        reply.WriteInt32(ret);
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    MainWindowStatesHandle::WriteMainWindowStatesVector(reply, mainWindowStates);
    return ERR_OK;
}

ErrCode GetAllMainWindowStatesPlugin::QueryMainWindowStates(int32_t userId,
    std::vector<MainWindowStates> &mainWindowStates)
{
    auto &windowManagerLite = Rosen::WindowManagerLite::GetInstance(userId);
    std::vector<Rosen::MainWindowInfo> mainWindowInfos;
    Rosen::WMError ret = windowManagerLite.GetAllMainWindowInfos(mainWindowInfos);
    if (ret != Rosen::WMError::WM_OK) { // LCOV_EXCL_BR_LINE
        EDMLOGE("GetAllMainWindowStatesPlugin GetAllMainWindowInfos failed, ret: %{public}d",
            static_cast<int32_t>(ret));
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    auto wmsProxy = Rosen::SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    if (wmsProxy == nullptr) { // LCOV_EXCL_BR_LINE
        EDMLOGE("GetAllMainWindowStatesPlugin wmsProxy is nullptr");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    // A process may have multiple main windows. Query window states once for each unique pid.
    std::map<int32_t, std::string> pidToBundleNames;
    for (const auto &info : mainWindowInfos) {
        if (info.pid_ <= 0) { // LCOV_EXCL_BR_LINE
            EDMLOGW("GetAllMainWindowStatesPlugin skip invalid pid: %{public}d", info.pid_);
            continue;
        }
        pidToBundleNames.emplace(info.pid_, info.bundleName_);
    }
    for (const auto &pidToBundleName : pidToBundleNames) {
        std::vector<Rosen::MainWindowState> windowStates;
        Rosen::WSError stateRet = wmsProxy->GetMainWindowStatesByPid(pidToBundleName.first, windowStates);
        if (stateRet != Rosen::WSError::WS_OK) { // LCOV_EXCL_BR_LINE
            EDMLOGE("GetAllMainWindowStatesPlugin GetMainWindowStatesByPid failed, pid: %{public}d, "
                "ret: %{public}d", pidToBundleName.first, static_cast<int32_t>(stateRet));
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
        }
        for (const auto &windowState : windowStates) {
            uint32_t state = static_cast<uint32_t>(windowState.state_);
            if (state > static_cast<uint32_t>(WindowState::BACKGROUND)) { // LCOV_EXCL_BR_LINE
                EDMLOGW("GetAllMainWindowStatesPlugin skip invalid window state: %{public}d, pid: %{public}d",
                    state, pidToBundleName.first);
                continue;
            }
            MainWindowStates mainWindowState;
            mainWindowState.pid = pidToBundleName.first;
            mainWindowState.bundleName = pidToBundleName.second;
            mainWindowState.state = WindowState(state);
            mainWindowStates.emplace_back(std::move(mainWindowState));
        }
    }
    return ERR_OK;
}
// LCOV_EXCL_STOP
} // namespace EDM
} // namespace OHOS
