#### Parser Content
```Java
{
Name = cise-remote-logon
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 60080 """, """A SSH CLI user has successfully logged in""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}60080)\s{1,100}({alert_severity}[^\s]+)\s({activity}[^:]+):\s{1,100}({event_name}[^,]+)"""
  ]
}
```