#### Parser Content
```Java
{
Name = cef-azure-security-alert
  Vendor = Microsoft
  Product = Azure Security Center
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""dproc=Graph Security Alerts""", """"provider":"ASC"""", """"category":"ARM_UnusedAccountPersistence"""", """PREVIEW - Suspicious management session using an inactive account detected""" ]
  Fields = [
    """\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s""",
    """"eventDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"IP address\\":\\"({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """"title":"({alert_name}[^"]{1,2000})"""",
    """"category":"({alert_type}[^"]{1,2000})"""",
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"Identity address\\":\\"({account_name}[^@"\\]{1,2000})@({domain}[^"\\]{1,2000})""",
    """"description":"({event_name}[^"]{1,2000})"""",
    """"Suspicious actions\\":\\"\[[\\"]{1,20}({additional_info}[^\]]{1,2000}?)[\\""]{1,20}\]"""
  ]


}
```