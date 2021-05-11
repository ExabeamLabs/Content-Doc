#### Parser Content
```Java
{
Name = microsoft-scep-epp-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """vendor=Microsoft product=""", """System Center Endpoint Protection""" ]
  Fields = [
    """dest_name=({dest_host}[^\s]+)\s""",
    """action_time="({time}[^"]+)"""",
    """alert_time="({time}[^"]+)"""",
    """user_id=({user}[\w\d]+)\s{1,100}dest_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}""",
    """severity=({alert_severity}[\w]+)\s{1,100}category=({alert_type}[^\s]+)\s{1,100}action""",
    """detection_id=({alert_id}[^\s]+)\s{1,100}""",
    """signature=({alert_name}[^\s]+)\s{1,100}""",
    """exabeam_host=({host}[\w\-.]+)""",
    """process="({process}[^"]+\\({process_name}[^"]+))"""",
  ]
  DupFields=[ "dest_ip->src_ip", "dest_host->src_host" ]
}
```