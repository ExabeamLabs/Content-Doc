#### Parser Content
```Java
{
Name = cise-remote-logon-1
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 51001 """, """Administrator authentication succeeded""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}51001)\s+({alert_severity}[^\s]+)\s({activity}[^:]+):\s+({event_name}[^,]+)"""
  ]
}
```