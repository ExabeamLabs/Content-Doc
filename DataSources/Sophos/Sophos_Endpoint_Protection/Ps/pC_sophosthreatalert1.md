#### Parser Content
```Java
{
Name = sophos-threat-alert-1
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, ThreatName="""", """, ActionTakenName="""", """, ThreatTypeName="""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """EventID="({alert_id}\d{1,100})""",
    """FirstDetectedAt="({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ThreatTypeName="({alert_type}[^"]{1,2000})""",
    """ThreatName="({alert_name}[^"]{1,2000})""",
    """ActionTakenName="({outcome}[^"]{1,2000})""",
    """FullFilePath="C:\\Users\\({user}[^\\]{1,2000})""",
    """UserName="((NT AUTHORITY|({domain}[^\\\s"]{1,2000}))\\+)?(SYSTEM|({user}[^\\\s"]{1,2000}))""",
    """ComputerName="({src_host}[\w\-.]{1,2000})""",
    """FullFilePath="({malware_url}[^"]{1,2000}?({malware_file_name}[^"\\]{1,2000}))"""",
  ]
}
```