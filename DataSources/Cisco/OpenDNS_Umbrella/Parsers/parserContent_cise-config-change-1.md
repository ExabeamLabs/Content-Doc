#### Parser Content
```Java
{
Name = cise-config-change-1
  DataType = "config-change"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 52000 """, """Added configuration""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}52000)\s+({alert_severity}[^\s]+)\s({activity}[^:]+):\s+({event_name}[^,]+)""",
    """ConfigChangeData=({action}.+?):*\s*\w+=""",
    """ObjectType=({file_type}[^,]+)""",
    """ObjectName=({file_name}[^,]+)"""
  ]
}
```