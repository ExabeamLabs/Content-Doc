#### Parser Content
```Java
{
Name = sophos-threat-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ThreatName=""","""ComputerIPAddress=""" ]
  Fields = [
    """;\s+EventID=({alert_id}[\d]+);""",
    """EventTime=({time}[\d\- :]+);""",
    """ThreatType=({alert_type}[^;]+);""",
    """FullFilePath=C:\\Users\\({user}[^\\]+)""",
    """ThreatName=({alert_name}[^;]+);""",
    """UserName=([^\\]+\\+)?(SYSTEM|({user}[^;]+))""",
    """ComputerName=({src_host}[^;]*);""",
    """ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[\w\-.]+)""",
    """FullFilePath=({file_path}[^;]+?)\s*(;|$)"""
  ]
}

{
  Name = sophos-threat-alert-1
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, ThreatName="""", """, ActionTakenName="""", """, ThreatTypeName="""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """EventID="({alert_id}\d+)""",
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