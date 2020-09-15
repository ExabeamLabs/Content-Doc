#### Parser Content
```Java
{
Name = crowdstrike-win-task-created
  DataType = "windows-task-created"
  Conditions = [ """"event_simpleName":"ScheduledTaskRegistered""", """"event_platform":"Win""""]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"TaskName":"({task_name}[^"]+)"""
  ]
}

${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp} {
  Name = crowdstrike-modify-binary
  DataType = "file-operations"
  Conditions = [ """event_simpleName""", """ModifyServiceBinary""" ]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"ServiceImagePath":"({file_path}({file_parent}[^"]*?\\+)({file_name}[^\\\s"]+?\.({file_ext}[^\\\s"\.]+?)))(\s|")"""
    """"ServiceObjectName":"({additional_info}[^"]+)"""
    """({accesses}Modify)"""
  ]
}

{
  Name = crowdstrike-app-activity
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"UserActivityAuditEvent"""", """"OperationName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"UserId":\s*"({user_email}[^"@]+@[^"@]+)"""",
    """"UserId":\s*"({user}[^"@]+)"""",
    """"UserIp":\s*"({src_ip}[^"]+)""",
    """"ServiceName":\s*"({resource}[^"]+)""",
    """({app}CrowdStrike)""",
    """"OperationName":\s*"({activity}[^",]+)""",
    """"AuditKeyValues":\[({additional_info}.+?)\]""",
    """"AuditKeyValues":[^\]]+?"Value(String)?":"({object}.*?[^\\])"(,|\})""",
  ]
}
```