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
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}""",
    """0\|F-Secure\|([^\|]{1,2000}\|){4}({alert_severity}\d{1,100})\|""",
    """(\s|\|)cs1=({malware_url}[^\s].+?)\s{1,100}(\w+=|$)""",
    """(\s|\|)act=({threat_category}[^\s].+?)\s{1,100}(\w+=|$)""",
    """(\s|\|)shost=({src_host}[^\s]{1,2000})""",
    """0\|F-Secure\|([^\|]{1,2000}\|){2}({alert_name}[^\|]{1,2000})\|""",
    """\WRiskware:({alert_name}[^\s]{1,2000})""",
    """Family:\s{1,100}Name:\s{0,100}({alert_name}[^\s]{1,2000})""",
    """(\s|\|)cs2=({alert_name}[^\s].+?)\s{1,100}(\w+=|$)""",
    """0\|F-Secure\|([^\|]{1,2000}\|){2}({alert_type}[^\|:]{1,2000}):""",
    """\WType:\s{0,100}({alert_type}[^\s]{1,2000})""",
    """(\s|\|)suser=(({domain}[^\\=]{1,2000})[\\]{1,2000})?({user}[^\\\s]{1,2000})""",
    """(\s|\|)msg=({additional_info}[^\s].+?)\s{1,100}(\w+=|$)"""
  ]
}
```