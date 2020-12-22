#### Parser Content
```Java
{
Name = vectra-alert
  Vendor = Vectra
  Product = Vectra Cognito Detect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """currentIP=""","""detection@""","""certainty="""]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """UTCTimeStart="+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """category="+({alert_type}[^"]+)"""",
    """type="+({alert_name}[^"]+)"""",
    """threat="+({alert_severity}[^"]+)"""",
    """hostname="+(?:IP-[\d.]+|({src_host}[^"]+))"""",
    """currentIP="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """DestinationIP="+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
}
```