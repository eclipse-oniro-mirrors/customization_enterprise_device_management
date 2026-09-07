# 07 - 错误码规范

> 来源 Bug: 错误码值冲突、STRING vs NUMBER 类型不一致、异步错误码未传递

## 规则 7.1：新接口错误码统一使用 NUMBER 类型

**错误根因**: 新接口错误码以 STRING 类型返回给 JS 侧，应使用 NUMBER 类型，导致类型不一致。

**来源**: 多个提交（`4deaa9cd`, `acd0d3e8`, `baedaae4`, `307abff5`, `085f80b7`, `e76bf125`）— `installForResult`、`deviceControl.OperateDevice` 等接口错误码为 STRING。

**正确做法**: 在 `AddonMethodSign` 中设置 `errcodeType = ErrcodeType::NUMBER`

```cpp
void XxxAddon::SetPolicyCommon(AddonMethodSign &addonMethodSign, int policyCode) {
    addonMethodSign.name = "setXxxPolicy";
    addonMethodSign.argsType = {EdmAddonCommonType::ELEMENT, EdmAddonCommonType::BOOLEAN};
    addonMethodSign.methodAttribute = MethodAttribute::HANDLE;
    addonMethodSign.policyCode = policyCode;
    addonMethodSign.errcodeType = ErrcodeType::NUMBER;  // 新接口必须用 NUMBER
}
```

**检查清单**:
- [ ] 所有新接口的 `AddonMethodSign.errcodeType` 必须设为 `ErrcodeType::NUMBER`
- [ ] 旧接口（已有 STRING 错误码的）在升级时应迁移为 NUMBER
- [ ] 错误码创建使用 `CreateErrorByType(env, ret, "", addonMethodSign.errcodeType)`

---

## 规则 7.2：错误码值不能与其他错误码冲突

**错误根因**: `EDM_ERR_UKEY_TIMEOUT` 错误码值 9201052 与 `FORM_TYPE_NOT_SUPPORT`（9201050）等分配有误。

**来源**: `e6ab56e2` — UKEY_TIMEOUT 从 9201050 改为 9201052（原值与 FORM_TYPE_NOT_SUPPORT 冲突）。

**检查清单**:
- [ ] 新增错误码时，检查 `edm_errors.h` 中是否已有相同值
- [ ] 错误码值应连续分配，新增时找到当前最大值 +1
- [ ] 错误码命名应清晰表达错误语义

```cpp
// common/native/include/edm_errors.h
namespace EdmReturnErrCode {
    constexpr uint32_t FORM_TYPE_NOT_SUPPORT = 9201050;
    constexpr uint32_t ADD_FORM_FAILED = 9201051;
    constexpr uint32_t EDM_ERR_UKEY_TIMEOUT = 9201052;  // 不能与上面冲突
    constexpr uint32_t SYSTEM_TIMER_MAX_COUNT_REACHED = 9201053;
};
```

---

## 规则 7.3：异步接口错误码必须通过 errcodeType 正确传递

**错误根因**: `AddonMethodAdapter` 未将 `methodSign.errcodeType` 传递给 `adapterAddonData`，导致异步回调中错误码类型错误。

**来源**: `816bd975` — 3 个异步接口错误码返回 STRING 而非 NUMBER。

详见 [03-napi-and-js-interop.md 规则 3.2](./03-napi-and-js-interop.md#规则-32addonmethodadapter-必须传递-errcodetype)。

**核心要求**:
```cpp
// napi_edm_adapter.cpp — AddonMethodAdapter
adapterAddonData->errcodeType = methodSign.errcodeType;  // 必须传递
```

**检查清单**:
- [ ] 新增异步接口后，测试 JS 侧收到的错误码是 number 还是 string
- [ ] 确认 `AddonMethodAdapter` 中 errcodeType 已正确传递

---

## 规则 7.4：异步接口不支持时必须返回正确错误码

**错误根因**: `StartCollectLog` 异步接口在设备不支持时应返回 801 错误码，但未正确返回。

**来源**: `c6d5f11b` — StartCollectLog 未返回 801。

**检查清单**:
- [ ] 异步接口在设备不支持/功能未开启时，必须返回正确的错误码（如 801）
- [ ] 不要静默返回成功，也不要返回通用的 SYSTEM_ABNORMALLY
- [ ] 错误码信息应该对用户有指导意义（说明哪个功能不支持）
