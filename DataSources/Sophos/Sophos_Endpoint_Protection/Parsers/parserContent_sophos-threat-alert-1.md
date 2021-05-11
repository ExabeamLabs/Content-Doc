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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """EventID="({alert_id}\d{1,100})""",
    """FirstDetectedAt="({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """ThreatTypeName="({alert_type}[^"]+)""",
    """ThreatName="({alert_name}[^"]+)""",
    """ActionTakenName="({outcome}[^"]+)""",
    """FullFilePath="C:\\Users\\({user}[^\\]+)""",
    """UserName="((NT AUTHORITY|({domain}[^\\\s"]+))\\+)?(SYSTEM|({user}[^\\\s"]+))""",
    """ComputerName="({src_host}[\w\-.]+)""",
    """FullFilePath="({malware_url}[^"]+?({malware_file_name}[^"\\]+))"""",
  ]
}
```