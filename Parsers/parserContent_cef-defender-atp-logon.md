#### Parser Content
```Java
{
Name = cef-defender-atp-logon
  DataType = "app-login"
  Conditions = ["""CEF""", """SkyFormation Cloud Apps Security""", """requestClientApplication=""", """AdvancedHunting-DeviceLogonEvents"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields} [
    """"LogonId"+:({logon_id}\d)""",
    """"DeviceName"+:\s*"+({dest_host}[^"]+)""",
    """"ActionType"+:\s*"+({outcome}.+?)","[^\\"]+":""""
  ]
}
```