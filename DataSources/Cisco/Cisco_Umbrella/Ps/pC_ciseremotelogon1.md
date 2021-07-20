#### Parser Content
```Java
{
Name = cise-remote-logon-1
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 51001 """, """Administrator authentication succeeded""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}51001)\s{1,100}({alert_severity}[^\s]{1,2000})\s({activity}[^:]{1,2000}):\s{1,100}({event_name}[^,]{1,2000})"""
  ]
}
```