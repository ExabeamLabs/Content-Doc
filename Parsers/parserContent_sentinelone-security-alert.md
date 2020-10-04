#### Parser Content
```Java
{
Name = sentinelone-security-alert-1
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ SentinelOne """, """[eventDesc@""", """[eventSeverity@""" ]
  Fields = [
    """\sdeviceAddress="({host}[a-fA-F\d.:]+)""",
    """\sdeviceHostName="({host}[^"]+)""",
    """\seventDesc="({alert_name}[^"]+)""",
    """\seventSeverity="({alert_severity}[^"]+)""",
    """\ssourceDnsDomain="({domain}[^"]+)""",
    """\ssourceUserName="(traps|({user}[^"]+))""",
    """\ssourceIpAddresses\.0="({src_ip}[^"]+)""",
    """\ssourceMacAddresses\.0="({src_mac}[^"]+)""",
    """\sthreatClassification="({alert_type}[^"]+)""",
    """\sthreatID="({alert_id}[^"]+)""",
    """\sfileName="({alert_name}[^"]+)""",
    """\s*fileContentHash="({md5}[^"]+)""",
    """\s*(D|d)etecting(E|e)ngine="({additional_info}[^"]+)""",
    """\screatedAt="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\Wcat="({category}[^"]+)""",
  ]
}
```