#### Parser Content
```Java
{
Name = cise-config-change-1
  DataType = "config-change"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 52000 """, """Added configuration""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}52000)\s{1,100}({alert_severity}[^\s]+)\s({activity}[^:]+):\s{1,100}({event_name}[^,]+)""",
    """ConfigChangeData=({action}.+?):*\s{0,100}\w+=""",
    """ObjectType=({file_type}[^,]+)""",
    """ObjectName=({file_name}[^,]+)"""
  ]
}
```