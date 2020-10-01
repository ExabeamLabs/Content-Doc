#### Parser Content
```Java
{
Name = s-cyberark-app-activity
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """%CYBERARK:""", """;Safe=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d\d\-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ %CYBERARK""",
    """\d\d:\d\d:\d\d(Z)? ({host}[\w\-.]+) %CYBERARK""",
    """MessageID="({event_code}\d+)""",
    """\d\d:\d\d:\d\d(Z)? ({app}[^\s]+) %CYBERARK:""",
    """;Message="({activity}[^"]+)""",
    """;Issuer="({user}[^"]+)""",
    """;Station="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;File="({file_path}[^"]+)""",
    """;File="({file_parent}[^"]+?)[^\\"]+"""",
    """;File="[^"]*?({file_name}[^\\"]+?)"""",
    """;File="[^"]*?\.({file_ext}[a-zA-Z]+?)";Safe=""",
    """;Safe="({safe_value}[^"]+)""",
    """;UserName="({account}[^"]+)""",
    """;LogonDomain="({domain}[^"]+)""",
    """;DeviceType="({dest_service}[^"]+)"""
  ]
  DupFields=[ "file_name->object_value", "file_path->additional_info", "activity->accesses", "host->dest_host" ]
}
```