#### Parser Content
```Java
{
Name = outlook-exchange-app-activity-1
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=SoftDelete""", """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-2
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=FolderBind""" , """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-3
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=HardDelete""" , """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-4
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=MailItemsAccessed""" , """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-5
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=MoveToDeletedItems""" , """CLIENTPROCESSNAME=""", """TS="""]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-6
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=Set-User""", """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-7
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=UpdateInboxRules""", """CLIENTPROCESSNAME=""", """TS=""" ]
}

${MSParserTemplates.outlook-exchange-app-activity} {
  Name = outlook-exchange-app-activity-8
  Conditions = [ """WORKLOAD=Exchange""", """COMMAND=Update""", """CLIENTPROCESSNAME=""", """TS=""" ]
}

{
  Name = azure-process-created-1
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Type":"VMProcess"""", """ExecutableName""" ]
  Fields = [
    """exabeam_host=([^=@]+@\s*)?({host}\S+)""",
    """"TimeGenerated":"({time}\d+-\d+-\d+T\d+:\d+:\d+)"""
    """Computer"+:"+({host}[^"]+)""",
    """Machine"+:"+({src_host}[^"]+)""",
    """ExecutableName"+:"+({process_name}[^"]+)""",
    """FirstPid"+:({pid}\d+)""",
    """ExecutablePath"+:"+({process_directory}[^.]+)\\({process}.+?)"+"""
    """CommandLine"+:"+({command_line}[^"]+)"+"""
    """UserName"+:"+(SYSTEM|({user}[^"]+))"""
    """UserDomain"+:"+({domain}[^"]+)"""
    ]
}
```