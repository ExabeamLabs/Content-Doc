#### Parser Content
```Java
{
Name = cef-defender-atp-member-removed
  DataType = "windows-member-removed"
  Conditions = ["""CEF:""", """|SkyFormation Cloud Apps Security|""", """requestClientApplication=""", """AdvancedHunting-DeviceEvents""","""UserAccountRemovedFromLocalGroup"""]
  Fields = ${MicrosoftParserTemplates.cef-defender-atp.Fields}[
  """"LogonId":(null|"({logon_id}[^"]{1,2000}))""",
  """AccountDomain":"({group_domain}[^"]{1,2000})"""
]
}
```