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
    """;\s{1,100}EventID=({alert_id}[\d]{1,2000});""",
    """EventTime=({time}[\d\- :]{1,2000});""",
    """ThreatType=({alert_type}[^;]{1,2000});""",
    """FullFilePath=C:\\Users\\({user}[^\\]{1,2000})""",
    """ThreatName=({alert_name}[^;]{1,2000});""",
    """UserName=([^\\]{1,2000}\\+)?(SYSTEM|({user}[^;]{1,2000}))""",
    """ComputerName=({src_host}[^;]{0,2000});""",
    """ComputerIPAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """FullFilePath=({file_path}[^;]{1,2000}?)\s{0,100}(;|$)""",
    """FullFilePath=({malware_url}[^;]{1,2000}\\({malware_file_name}[^;]{1,2000}))""",
    """Status=({alert_severity}[^;]{1,2000})""",
  ]
}
```