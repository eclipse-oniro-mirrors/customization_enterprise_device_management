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

#include "histograms_report.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#ifdef API_METRICS_EDM_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS {
namespace EDM {
#ifdef API_METRICS_EDM_ENABLE
const int32_t REPORT_SUCCESS = 1;
#endif

std::unordered_map<uint32_t, std::string> HistogramsReport::setCodeReportNameMap = {
    {EdmInterfaceCode::ADD_OS_ACCOUNT, "MdmKit.accountManager.addOsAccountAsync.ApiCall"},
    {EdmInterfaceCode::MANAGE_AUTO_START_APPS, "MdmKit.applicationManager.addAutoStartApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS, "MdmKit.applicationManager.addKeepAliveApps.ApiCall"},
    {EdmInterfaceCode::ALLOWED_KIOSK_APPS, "MdmKit.applicationManager.setAllowedKioskApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS, "MdmKit.applicationManager.addUserNonStopApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS, "MdmKit.applicationManager.addFreezeExemptedApps.ApiCall"},
    {EdmInterfaceCode::SET_ABILITY_ENABLED, "MdmKit.applicationManager.setAbilityDisabled.ApiCall"},
    {EdmInterfaceCode::SET_BROWSER_POLICIES, "MdmKit.browser.setPolicySync.ApiCall"},
    {EdmInterfaceCode::MANAGED_BROWSER_POLICY, "MdmKit.browser.setManagedBrowserPolicy.ApiCall"},
    {EdmInterfaceCode::INSTALL, "MdmKit.bundleManager.install.ApiCall"},
    {EdmInterfaceCode::UNINSTALL, "MdmKit.bundleManager.uninstall.ApiCall"},
    {EdmInterfaceCode::INSTALL_MARKET_APPS, "MdmKit.bundleManager.installMarketApps.ApiCall"},
    {EdmInterfaceCode::DISABLED_NETWORK_INTERFACE, "MdmKit.networkManager.setNetworkInterfaceDisabled.ApiCall"},
    {EdmInterfaceCode::FIREWALL_RULE, "MdmKit.networkManager.addFirewallRule.ApiCall"},
    {EdmInterfaceCode::DOMAIN_FILTER_RULE, "MdmKit.networkManager.addDomainFilterRule.ApiCall"},
    {EdmInterfaceCode::PASSWORD_POLICY, "MdmKit.securityManager.setPasswordPolicy.ApiCall"},
    {EdmInterfaceCode::INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE,
        "MdmKit.securityManager.installEnterpriseReSignatureCertificate.ApiCall"},
    {EdmInterfaceCode::PERMISSION_MANAGED_STATE, "MdmKit.securityManager.setPermissionManagedState.ApiCall"},
    {EdmInterfaceCode::SET_OTA_UPDATE_POLICY, "MdmKit.systemManager.setOtaUpdatePolicy.ApiCall"},
    {EdmInterfaceCode::NOTIFY_UPGRADE_PACKAGES, "MdmKit.systemManager.notifyUpdatePackages.ApiCall"},
    {EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED,
        "MdmKit.systemManager.setInstallLocalEnterpriseAppEnabled.ApiCall"},
    {EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT,
        "MdmKit.systemManager.setInstallLocalEnterpriseAppEnabledForAccount.ApiCall"},
    {EdmInterfaceCode::SET_KEY_CODE_POLICYS, "MdmKit.systemManager.addKeyEventPolicies.ApiCall"},
    {EdmInterfaceCode::DISABLED_ACTIVATION_LOCK, "MdmKit.systemManager.setActivationLockDisabled.ApiCall"},
    {EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG,
        "MdmKit.systemManager.startCollectLog.ApiCall"},
    {EdmInterfaceCode::SET_WIFI_PROFILE, "MdmKit.wifiManager.setWifiProfileSync.ApiCall"},
};

std::unordered_map<uint32_t, std::string> HistogramsReport::removeCodeReportNameMap = {
    {EdmInterfaceCode::MANAGE_AUTO_START_APPS, "MdmKit.applicationManager.removeAutoStartApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_KEEP_ALIVE_APPS, "MdmKit.applicationManager.removeKeepAliveApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_USER_NON_STOP_APPS, "MdmKit.applicationManager.removeUserNonStopApps.ApiCall"},
    {EdmInterfaceCode::MANAGE_FREEZE_EXEMPTED_APPS, "MdmKit.applicationManager.removeFreezeExemptedApps.ApiCall"},
    {EdmInterfaceCode::FIREWALL_RULE, "MdmKit.networkManager.removeFirewallRule.ApiCall"},
    {EdmInterfaceCode::DOMAIN_FILTER_RULE, "MdmKit.networkManager.removeDomainFilterRule.ApiCall"},
    {EdmInterfaceCode::INSTALL_ENTERPRISE_RE_SIGNATURE_CERTIFICATE,
        "MdmKit.securityManager.uninstallEnterpriseReSignatureCertificate.ApiCall"},
    {EdmInterfaceCode::SET_KEY_CODE_POLICYS, "MdmKit.systemManager.removeKeyEventPolicies.ApiCall"},
    {EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::START_COLLECT_LOG,
        "MdmKit.systemManager.finishLogCollected.ApiCall"},
};

bool HistogramsReport::ReportBoolean(uint32_t code)
{
    EDMLOGI("HistogramsReport::ReportBoolean code: %{public}d", code);
    std::string reportName;
    if (!GetReportNameByCode(FuncCodeUtils::GetOperateType(code), FuncCodeUtils::GetPolicyCode(code), reportName)) {
        EDMLOGW("HistogramsReport::ReportBoolean GetReportNameByCode %{public}d not found", code);
        return false;
    }
    ReportBoolean(reportName);
    return true;
}

void HistogramsReport::ReportBoolean(const std::string &reportName)
{
#ifdef API_METRICS_EDM_ENABLE
    EDMLOGI("HistogramsReport::ReportBoolean reportName: %{public}s", reportName.c_str());
    HISTOGRAM_BOOLEAN(reportName, REPORT_SUCCESS);
#endif
}

bool HistogramsReport::GetReportNameByCode(FuncOperateType type, uint32_t ipcCode, std::string &reportName)
{
    if (type != FuncOperateType::SET && type != FuncOperateType::REMOVE) {
        return false;
    }
    auto &codeReportNameMap = (type == FuncOperateType::SET) ? setCodeReportNameMap : removeCodeReportNameMap;
    auto it = codeReportNameMap.find(ipcCode);
    if (it == codeReportNameMap.end()) {
        return false;
    }
    reportName = it->second;
    return true;
}
} // namespace EDM
} // namespace OHOS