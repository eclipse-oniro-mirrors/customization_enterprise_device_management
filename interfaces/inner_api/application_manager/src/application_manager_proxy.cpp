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
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<ApplicationManagerProxy> ApplicationManagerProxy::instance_ = nullptr;
std::once_flag ApplicationManagerProxy::flag_;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";

std::shared_ptr<ApplicationManagerProxy> ApplicationManagerProxy::GetApplicationManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<ApplicationManagerProxy>();
        }
    });
    return instance_;
}

int32_t ApplicationManagerProxy::AddDisallowedRunningBundles(AppExecFwk::ElementName &admin,
    std::vector<std::string> &bundles, int32_t userId, bool isSync)
{
    EDMLOGD("ApplicationManagerProxy::AddDisallowedRunningBundles");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
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
    reply.ReadStringVector(&bundles);
    return ERR_OK;
}

int32_t ApplicationManagerProxy::AddOrRemoveAutoStartApps(MessageParcel &data, bool isAdd)
{
    EDMLOGD("ApplicationManagerProxy::AddOrRemoveAutoStartApps");
    FuncOperateType operateType = isAdd ? FuncOperateType::SET : FuncOperateType::REMOVE;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)operateType, EdmInterfaceCode::MANAGE_AUTO_START_APPS);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::GetAutoStartApps(MessageParcel &data,
    std::vector<AppExecFwk::ElementName> &autoStartApps)
{
    EDMLOGD("ApplicationManagerProxy::GetAutoStartApps");
    MessageParcel reply;
    EnterpriseDeviceMgrProxy::GetInstance()->GetPolicy(EdmInterfaceCode::MANAGE_AUTO_START_APPS, data, reply);
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

int32_t ApplicationManagerProxy::AddKeepAliveApps(const AppExecFwk::ElementName &admin,
    const std::vector<std::string> &keepAliveApps, int32_t userId, std::string &retMessage)
{
    EDMLOGI("ApplicationManagerProxy::AddKeepAliveApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(keepAliveApps);
    ErrCode ret = proxy->HandleDevicePolicy(funcCode, data, reply);
    if (ret != ERR_OK) {
        retMessage = reply.ReadString();
        return ret;
    }
    return ERR_OK;
}

int32_t ApplicationManagerProxy::RemoveKeepAliveApps(const AppExecFwk::ElementName &admin,
    const std::vector<std::string> &keepAliveApps, int32_t userId)
{
    EDMLOGI("ApplicationManagerProxy::RemoveKeepAliveApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::REMOVE, EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(keepAliveApps);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::GetKeepAliveApps(const AppExecFwk::ElementName &admin,
    std::vector<std::string> &keepAliveApps, int32_t userId)
{
    EDMLOGI("ApplicationManagerProxy::GetKeepAliveApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(HAS_USERID);
    data.WriteInt32(userId);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    proxy->GetPolicy(EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS, data, reply);
    
    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy::GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&keepAliveApps);
    return ERR_OK;
}

int32_t ApplicationManagerProxy::SetKioskFeatures(MessageParcel &data)
{
    EDMLOGD("ApplicationManagerProxy::SetKioskFeatures");
    MessageParcel reply;
    std::uint32_t funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::SET_KIOSK_FEATURE);
    return EnterpriseDeviceMgrProxy::GetInstance()->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::ClearUpApplicationData(
    const AppExecFwk::ElementName &admin, const ClearUpApplicationDataParam &param)
{
    EDMLOGI("ApplicationManagerProxy::ClearUpApplicationData");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
        POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::CLEAR_UP_APPLICATION_DATA);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    MessageParcelUtils::WriteClearUpApplicationDataParam(param, data);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::SetAllowedKioskApps(
    const AppExecFwk::ElementName &admin, const std::vector<std::string> &bundleNames)
{
    EDMLOGI("ApplicationManagerProxy::SetAllowedKioskApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    std::uint32_t funcCode =
            POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, EdmInterfaceCode::ALLOWED_KIOSK_APPS);
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteParcelable(&admin);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteStringVector(bundleNames);
    return proxy->HandleDevicePolicy(funcCode, data);
}

int32_t ApplicationManagerProxy::GetAllowedKioskApps(
    const AppExecFwk::ElementName &admin, std::vector<std::string> &bundleNames)
{
    EDMLOGI("ApplicationManagerProxy::GetAllowedKioskApps");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(HAS_ADMIN);
    data.WriteParcelable(&admin);
    proxy->GetPolicy(EdmInterfaceCode::ALLOWED_KIOSK_APPS, data, reply);

    int32_t ret = ERR_INVALID_VALUE;
    bool blRes = reply.ReadInt32(ret) && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("EnterpriseDeviceMgrProxy::GetPolicy fail. %{public}d", ret);
        return ret;
    }
    reply.ReadStringVector(&bundleNames);
    return ERR_OK;
}

int32_t ApplicationManagerProxy::IsAppKioskAllowed(const std::string &bundleName, bool &isAllowed)
{
    EDMLOGI("ApplicationManagerProxy::IsAppKioskAllowed");
    auto proxy = EnterpriseDeviceMgrProxy::GetInstance();
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(DESCRIPTOR);
    data.WriteInt32(WITHOUT_USERID);
    data.WriteString(WITHOUT_PERMISSION_TAG);
    data.WriteInt32(WITHOUT_ADMIN);
    data.WriteString(bundleName);
    proxy->GetPolicy(EdmInterfaceCode::IS_APP_KIOSK_ALLOWED, data, reply);
    int32_t ret = ERR_INVALID_VALUE;
    int32_t readRet = reply.ReadInt32(ret);
    if (readRet && (ret == EdmReturnErrCode::ADMIN_INACTIVE)) {
        isAllowed = false;
        return ERR_OK;
    }
    bool blRes = readRet && (ret == ERR_OK);
    if (!blRes) {
        EDMLOGW("ApplicationManagerProxy::IsAppKioskAllowed fail. %{public}d", ret);
        return ret;
    }
    reply.ReadBool(isAllowed);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
