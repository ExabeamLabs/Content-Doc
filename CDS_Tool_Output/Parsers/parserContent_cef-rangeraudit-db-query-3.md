#### Parser Content
```Java
{
Name = cef-rangeraudit-db-query-3
  Conditions = [ """"RangerAudit"""", """access""", """"USE"""" ]
}

${RAParserTemplates.cef-rangeraudit-db-query} {
  Name = cef-rangeraudit-db-query-4
  Conditions = [ """"RangerAudit"""", """access""", """"CREATE"""" ]
}

${RAParserTemplates.cef-rangeraudit-db-query} {
  Name = cef-rangeraudit-db-query-5
  Conditions = [ """"RangerAudit"""", """access""", """"DROP"""" ]
}

${RAParserTemplates.cef-rangeraudit-db-query} {
  Name = cef-rangeraudit-db-query-6
  Conditions = [ """"RangerAudit"""", """access""", """"UPDATE"""" ]
}

${RAParserTemplates.cef-rangeraudit-db-query} {
  Name = cef-rangeraudit-db-query-7
  Conditions = [ """"RangerAudit"""", """access""", """"MASK_NULL"""" ]
}

{
  Name = cef-rangeraudit-file-operations
  Vendor = RangerAudit 
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"RangerAudit"""", """resType""", """"path"""" ]
  Fields = [
    """evtTime"*:"({time}[^"]+)""",
    """agentHost"*:"({host}[^"]+)""",
    """repo"*:"({app}[^"]+)""",
    """reqUser"*:"({user}[^"]+)""",
    """access"*:"({accesses}[^"]+)""",
    """resource"*:"({file_path}[^"]+)""",
    """action"*:"({action}[^"]+)""",
    """cliIP"*:"({src_ip}[^"]+)""",
    """cluster_name"*:"({dest_host}[^"]+)""",
  ]
}
```