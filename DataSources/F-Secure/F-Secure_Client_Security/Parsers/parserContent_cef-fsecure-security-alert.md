#### Parser Content
```Java
{
Name = cef-fsecure-security-alert
  Vendor = F-Secure
  Product = F-Secure Client Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MM dd yyyy HH:mm:ss"
  Conditions = [ """|F-Secure|F-Secure Client Security Premium|""", """domainTreePath=""", """msg=""" ]
  Fields = [
    """(exabeam_\w+=|^)({time}\d\d \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}""",
    """0\|F-Secure\|([^\|]+\|){4}({alert_severity}\d{1,100})\|""",
    """(\s|\|)cs1=({malware_url}[^\s].+?)\s{1,100}(\w+=|$)""",
    """(\s|\|)act=({threat_category}[^\s].+?)\s{1,100}(\w+=|$)""",
    """(\s|\|)shost=({src_host}[^\s]+)""",
    """0\|F-Secure\|([^\|]+\|){2}({alert_name}[^\|]+)\|""",
    """\WRiskware:({alert_name}[^\s]+)""",
    """Family:\s{1,100}Name:\s{0,100}({alert_name}[^\s]+)""",
    """(\s|\|)cs2=({alert_name}[^\s].+?)\s{1,100}(\w+=|$)""",
    """0\|F-Secure\|([^\|]+\|){2}({alert_type}[^\|:]+):""",
    """\WType:\s{0,100}({alert_type}[^\s]+)""",
    """(\s|\|)suser=(({domain}[^\\=]+)[\\]+)?({user}[^\\\s]+)""",
    """(\s|\|)msg=({additional_info}[^\s].+?)\s{1,100}(\w+=|$)"""
  ]
}
```