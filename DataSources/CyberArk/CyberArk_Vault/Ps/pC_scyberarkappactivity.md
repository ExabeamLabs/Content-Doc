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
    """\d\d:\d\d:\d\d(Z)? ({host}[\w\-.]{1,2000}) %CYBERARK""",
    """MessageID="({event_code}\d{1,100})""",
    """\d\d:\d\d:\d\d(Z)? ({app}[^\s]{1,2000}) %CYBERARK:""",
    """;Message="({activity}[^"]{1,2000})""",
    """;Issuer="({user}[^"]{1,2000})""",
    """;Station="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """;File="({file_path}[^"]{1,2000})""",
    """;File="({file_parent}[^"]{1,2000}?)[^\\"]{1,2000}"""",
    """;File="[^"]{0,2000}?({file_name}[^\\"]{1,2000}?)"""",
    """;File="[^"]{0,2000}?\.({file_ext}[a-zA-Z]{1,2000}?)";Safe=""",
    """;Safe="({safe_value}[^"]{1,2000})""",
    """;UserName ="({account}[^"]{1,2000})""",
    """;LogonDomain="({domain}[^"]{1,2000})""",
    """;DeviceType="({dest_service}[^"]{1,2000})"""
  ]
  DupFields=[ "file_name->object_value", "file_path->additional_info", "activity->accesses", "host->dest_host" ]


}
```