#### Parser Content
```Java
{
Name = s-cyberark-file-read-2
  DataType = "file-read"
  Conditions = [ """%CYBERARK:""", """Message="Retrieve File""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;File="({file_path}[^"]+)""",
    """;File="({file_parent}[^"]+?)[^\\"]+"""",
    """;File="[^"]*?({file_name}[^\\"]+?)"""",
    """;File="[^"]*?\.({file_ext}[a-zA-Z]+?)";Safe=""",
    """;LogonDomain="(|({domain}[^"]+))"""",
  ]
  DupFields=[ "file_name->object_value", "file_path->additional_info", "activity->accesses", "host->dest_host" ]
}
```