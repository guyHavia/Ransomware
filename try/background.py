import winreg as reg

reg.DeleteKey(reg.HKEY_LOCAL_MACHINE, r'SYSTEM\encryption')

