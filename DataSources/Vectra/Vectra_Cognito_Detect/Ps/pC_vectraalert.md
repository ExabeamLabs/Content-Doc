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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """UTCTimeStart="{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """category="{1,20}({alert_type}[^"]{1,2000})"""",
    """type="{1,20}({alert_name}[^"]{1,2000})"""",
    """threat="{1,20}({alert_severity}[^"]{1,2000})"""",
    """hostname="{1,20}(?:IP-[\d.]{1,2000}|({src_host}[^"]{1,2000}))"""",
    """currentIP="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """DestinationIP="{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
}
```