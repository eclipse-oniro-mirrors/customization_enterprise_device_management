    /**
     * @tc.name   test_device_settings_remove_hidden_settings_menu_0109
     * @tc.number SUB_CUSTOMIZATION_EDM_DEVICE_SETTINGS_REMOVE_HIDDEN_SETTINGS_MENU_JS_0109
     * @tc.desc   test add hidden settings menu success
     * @tc.type   FUNCTION
     * @tc.size   MEDIUMTEST
     * @tc.level  LEVEL2
     */
    it("test_device_settings_remove_hidden_settings_menu_0109", Level.LEVEL2, async (done: Function) => {
      await adminManager.enableAdmin(SELFWANT, ENTINFO1, adminManager.AdminType.ADMIN_TYPE_SUPER);
      try {
        deviceSettings.removeHiddenSettingsMenu(SELFWANT, FULL_VALID_MENUS_TO_HIDE);
        const removeResultList: Array<number> = deviceSettings.getHiddenSettingsMenu(SELFWANT) as Array<number>;
        expect(removeResultList.length).assertEqual(0);
      } catch (error) {
        expect(error.code === 801).assertTrue();
      } finally {
        await adminManager.disableSuperAdmin(SELFHAPNAME);
      }
      done();
    });