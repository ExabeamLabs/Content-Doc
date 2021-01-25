#### Parser Content
```Java
{
Name = crowdstrike-logon-2
  DataType = "file-operations"
  Conditions = [ """"event_simpleName\":\"UserLogon\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
    """"LogonType\\*"+:\\*"+({logon_type}\d+)""",
    """"LogonDomain\\*"+:\\*"+({domain}[^"\\]+)""",
    """"ClientComputerName\\*"+:\\*"+({dest_host}[^"\\]+)""",
  ]
}
```