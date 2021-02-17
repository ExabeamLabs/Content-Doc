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
```