#### Parser Content
```Java
{
Name = cef-sysmon-file-write-2
  DataType = "registry-write"
  Conditions = [ """CEF:""", """|Microsoft Sysmon|Sysmon NXLog|""", """|SysmonTask-SYSMON_REG_SETVALUE|Registry value set|""" ]
}
```