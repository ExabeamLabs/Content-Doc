#### Parser Content
```Java
{
Name = cise-remote-logon-3
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 60115 """, """A CLI user has logged in from SSH""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}60115)\s+({alert_severity}[^\s]+)\s({activity}[^:]+):\s+({event_name}[^,]+)"""
  ]
}
```