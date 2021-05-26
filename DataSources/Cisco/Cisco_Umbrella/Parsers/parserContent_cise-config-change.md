#### Parser Content
```Java
{
Name = cise-config-change
  DataType = "config-change"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 52001 """, """Changed configuration""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}52001)\s{1,100}({alert_severity}[^\s]{1,2000})\s({activity}[^:]{1,2000}):\s{1,100}({event_name}[^,]{1,2000})""",
    """ConfigChangeData=({action}[^:]{1,2000})""",
    """FailureFlag=({failure_flag}[^,]{1,2000})""",
    """ObjectName=({object}[^,]{1,2000})"""
  ]
}
```