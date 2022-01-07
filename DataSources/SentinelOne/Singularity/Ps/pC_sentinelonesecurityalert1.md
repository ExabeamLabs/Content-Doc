#### Parser Content
```Java
{
Name = sentinelone-security-alert-1
  Vendor = SentinelOne
  Product = Singularity 
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ SentinelOne """, """[eventDesc@""", """[eventSeverity@""" ,"""cat="MALWARE"""]
  Fields = [
    """\sdeviceAddress="({host}[a-fA-F\d.:]{1,2000})""",
    """\sdeviceHostName ="({host}[^"]{1,2000})""",
    """\seventDesc="({alert_name}[^"]{1,2000})""",
    """\seventSeverity="({alert_severity}[^"]{1,2000})""",
    """\ssourceDnsDomain="({domain}[^"]{1,2000})""",
    """\ssourceUserName ="(traps|({user}[^"]{1,2000}))""",
    """\ssourceIpAddresses\.0="({src_ip}[^"]{1,2000})""",
    """\ssourceMacAddresses\.0="({src_mac}[^"]{1,2000})""",
    """\sthreatClassification="({alert_type}[^"]{1,2000})""",
    """\sthreatID="({alert_id}[^"]{1,2000})""",
    """\sfileName ="({alert_name}[^"]{1,2000})""",
    """\s{0,100}fileContentHash="({md5}[^"]{1,2000})""",
    """\s{0,100}(D|d)etecting(E|e)ngine="({additional_info}[^"]{1,2000})""",
    """\screatedAt="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\Wcat="({category}[^"]{1,2000})""",
    """\sdata.filePath="({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))""",
  ]


}
```