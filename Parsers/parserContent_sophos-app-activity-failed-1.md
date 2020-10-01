#### Parser Content
```Java
{
Name = sophos-app-activity-failed-1
  DataType = "app-activity"
  Conditions = [ """Action=Blocked;""", """EventType=Adware or PUA;""", """ReportingName=""", """ComputerIPAddress="""  ] 
  Fields=${SophosParserTemplates.sophos-endpoint-events.Fields}[
    """SubType=({failure_reason}[^;]+)"""
  ]
}
```