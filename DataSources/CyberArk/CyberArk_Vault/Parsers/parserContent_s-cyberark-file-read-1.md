#### Parser Content
```Java
{
Name = s-cyberark-file-read-1
  DataType = "file-read"
  Conditions = [ """%CYBERARK:""", """Message="Open File"""", """;Safe=""" ]
  Fields = ${CyberArkParserTemplates.s-cyberark-events.Fields} [
    """;File="({file_path}[^"]{1,2000})""",
    """;File="({file_parent}[^"]{1,2000}?)[^\\"]{1,2000}"""",
    """;File="[^"]{0,2000}?({file_name}[^\\"]{1,2000}?)"""",
    """;File="[^"]{0,2000}?\.({file_ext}[a-zA-Z]{1,2000}?)";Safe=""",
    """;LogonDomain="(|({domain}[^"]{1,2000}))"""",
  ]
  DupFields=[ "file_name->object_value", "file_path->additional_info", "activity->accesses", "host->dest_host" ]
}
```