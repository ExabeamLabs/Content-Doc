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
    """UTCTimeStart="{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """category="{1,20}({alert_type}[^"]+)"""",
    """type="{1,20}({alert_name}[^"]+)"""",
    """threat="{1,20}({alert_severity}[^"]+)"""",
    """hostname="{1,20}(?:IP-[\d.]+|({src_host}[^"]+))"""",
    """currentIP="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """DestinationIP="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
}
```