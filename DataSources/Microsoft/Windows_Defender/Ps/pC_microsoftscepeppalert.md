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
    """dest_name=({dest_host}[^\s]{1,2000})\s""",
    """action_time="({time}[^"]{1,2000})"""",
    """alert_time="({time}[^"]{1,2000})"""",
    """user_id=({user}[\w\d]{1,2000})\s{1,100}dest_ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{1,100}""",
    """severity=({alert_severity}[\w]{1,2000})\s{1,100}category=({alert_type}[^\s]{1,2000})\s{1,100}action""",
    """detection_id=({alert_id}[^\s]{1,2000})\s{1,100}""",
    """signature=({alert_name}[^\s]{1,2000})\s{1,100}""",
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """process="({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))"""",
  ]
  DupFields=[ "dest_ip->src_ip", "dest_host->src_host" ]
}
```