/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "application_manager_proxy.h"

#include "edm_constants.h"
#include "edm_log.h"
#include "func_code.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<ApplicationManagerProxy> ApplicationManagerProxy::instance_ = nullptr;
std::mutex ApplicationManagerProxy::mutexLock_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<ApplicationManagerProxy> ApplicationManagerProxy::GetApplicationManagerProxy()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutexLock_);
        if (instance_ == nullptr) {
            std::shared_ptr<ApplicationManagerProxy> temp = std::make_shared<ApplicationManagerProxy>();
            instance_ = temp;
        }
    }
    return instance_;
}

int32_t ApplicationManagerProxy::AddDisallowedRunningBundles(AppExecFwk::ElementName &admin,
    std::vector<std::string> &bundles, int32_t userId, bool isSync)
{
    EDMLOGD("ApplicationManagerProxy::AddDisallowedRunningBundles");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::RemoveDisallowedRunningBundles(AppExecFwk::ElementName &admin,
    std::vector<std::string> &bundles, int32_t userId, bool isSync)
{
    EDMLOGD("ApplicationManagerProxy::RemoveDisallowedRunningBundles");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteStringVector(bundles);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::GetDisallowedRunningBundles(AppExecFwk::ElementName &admin, int32_t userId,
    std::vector<std::string> &bundles, bool isSync)
{
    EDMLOGD("ApplicationManagerProxy::GetDisallowedRunningBundles");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteString(isSync ? EdmConstants::PERMISSION_TAG_VERSION_12 : EdmConstants::PERMISSION_TAG_VERSION_11);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::DISALLOW_RUNNING_BUNDLES, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    int32_t size = reply.ReadInt32();
    if (size > EdmConstants::APPID_MAX_SIZE) {
        EDMLOGE("bundles size=[%{public}d] is too large", size);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.ReadStringVector(&bundles);
    return ERR_OK;
}

int32_t ApplicationManagerProxy::AddAutoStartApps(const AppExecFwk::ElementName &admin,
    const std::vector<AppExecFwk::ElementName> &autoStartApps)
{
    EDMLOGD("ApplicationManagerProxy::AddAutoStartApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    std::vector<std::string> autoStartAppsString;
    for (size_t i = 0; i < autoStartApps.size(); i++) {
        std::string appWant = autoStartApps[i].GetBundleName() + "/" + autoStartApps[i].GetAbilityName();
        autoStartAppsString.push_back(appWant);
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(autoStartAppsString);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::RemoveAutoStartApps(const AppExecFwk::ElementName &admin,
    const std::vector<AppExecFwk::ElementName> &autoStartApps)
{
    EDMLOGD("ApplicationManagerProxy::RemoveAutoStartApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    std::vector<std::string> autoStartAppsString;
    for (size_t i = 0; i < autoStartApps.size(); i++) {
        std::string appWant = autoStartApps[i].GetBundleName() + "/" + autoStartApps[i].GetAbilityName();
        autoStartAppsString.push_back(appWant);
    }
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(autoStartAppsString);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::GetAutoStartApps(const AppExecFwk::ElementName &admin,
    std::vector<AppExecFwk::ElementName> &autoStartApps)
{
    EDMLOGD("ApplicationManagerProxy::GetAutoStartApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    if (proxy == nullptr) {
        EDMLOGE("can not get EnterpriseDeviceMgrProxy");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::MANAGE_AUTO_START_APPS, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy:GetPolicy fail. %{public}d", ret);
        return ret;
    }
    std::vector<std::string> autoStartAppsString;
    reply.ReadStringVector(&autoStartAppsString);
    for (size_t i = 0; i < autoStartAppsString.size(); i++) {
        size_t index = autoStartAppsString[i].find("/");
        std::string bundleName;
        std::string abilityName;
        if (index != autoStartAppsString[i].npos) {
            bundleName = autoStartAppsString[i].substr(0, index);
            abilityName = autoStartAppsString[i].substr(index + 1);
        } else {
            EDMLOGE("GetAutoStartApps parse auto start app want failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        AppExecFwk::ElementName element;
        element.SetBundleName(bundleName);
        element.SetAbilityName(abilityName);
        autoStartApps.push_back(element);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
