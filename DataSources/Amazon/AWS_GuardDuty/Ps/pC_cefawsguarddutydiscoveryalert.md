#### Parser Content
```Java
{
Name = cef-aws-guardduty-discovery-alert
  Vendor = Amazon
  Product = AWS GuardDuty
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =AWS""", """dproc=GuardDuty""", """Type: Discovery:S3/TorIPCaller""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """CreatedAt:\s{0,100}({time}\d{4}-\d{2}-\d{2}T(\d{2}:){2}\d{2}\.\d+?Z),""",
    """IpAddressV4:\s{0,100}({src_ip}(\d{1,3}\.){3}\d{1,3}),""",
    """Title:\s{0,100}({event_name}[^:]{1,2000}?),\w+?:""",
    """,Type:\s{0,100}({alert_type}[^:]{1,2000}?):({alert_name}[^:]{1,2000}?),\w+?:""",
    """Severity:\s{0,100}({alert_severity}[\d.]{1,2000}),""",
    """Region:\s{0,100}({region}[^:]{1,2000}?),\w+?:""",
    """Description:\s{0,100}({additional_info}[^:]{1,2000}?),\w+?:""",
    """AccountId:\s{0,100}({account_id}[^:]{1,2000}?),\w+?:""",
    """Resource:[^}]{1,2000}PrincipalId:\s{0,100}([^

}
```