#### Parser Content
```Java
{
Name = windows-vpn-login-failed-4654
  DataType = "failed-vpn-login"
  Conditions = [ """(4654)""", """[WIN]""", """Microsoft-Windows-Security-Auditing""" ]
  Fields = ${WinParserTemplates.windows-vpn-direct-access.Fields} [
    """({event_name}An IPsec quick mode negotiation failed)"""
    """({outcome}failed)""",
  ]
}
```