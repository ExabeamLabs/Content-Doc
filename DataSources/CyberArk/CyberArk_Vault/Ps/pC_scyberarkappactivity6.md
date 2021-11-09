#### Parser Content
```Java
{
Name = s-cyberark-app-activity-6
  DataType = "app-activity"
  Conditions = [ """%CYBERARK:""", """Message="PSM Secure Connect Session End""", """;Safe=""" ]
}
s-cyberark-events {
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ) \S+ %CYBERARK""",
    """\d\d:\d\d:\d\d(Z)? ({host}[\w\-.]{1,2000}) %CYBERARK""",
    """({app}CYBERARK)""",
    """;Message="(|({activity}[^"]{1,2000}?))\s{0,100}"""",
    """MessageID="({event_code}\d{1,100})""",
    """;Issuer="({user}[^"]{1,2000})""",
    """;Station="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """;Safe="(|({safe_value}[^"]{1,2000}))"""",
    """;UserName="(|(({domain}[^\s\\"]{1,2000})\\+)?({account}[^\s\\"]{1,2000}))"""",
    """;LogonDomain="(|[\d\.]{1,2000}|({account_domain}[^"]{1,2000}?))"""",
    """;DeviceType="(|({dest_service}[^"]{1,2000}))"""",
    """;Address="(|(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\:({dest_port}\d{1,100}))?|({dest_host}[\w\-.]{1,2000})))""""
  ]}
```