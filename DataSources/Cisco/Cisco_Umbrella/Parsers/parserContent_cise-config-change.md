#### Parser Content
```Java
{
Name = cise-config-change
  DataType = "config-change"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 52001 """, """Changed configuration""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}52001)\s{1,100}({alert_severity}[^\s]+)\s({activity}[^:]+):\s{1,100}({event_name}[^,]+)""",
    """ConfigChangeData=({action}[^:]+)""",
    """FailureFlag=({failure_flag}[^,]+)""",
    """ObjectName=({object}[^,]+)"""
  ]
}
```