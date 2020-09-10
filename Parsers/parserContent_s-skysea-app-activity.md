#### Parser Content
```Java
{
Name = s-skysea-app-activity
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",起動・終了," ]
  Fields = [
    """exabeam_raw=({host}[^\,]+)\,""",
    """^([^\,]*\,){2}({src_host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){5}({user}[^\,]+)\,""",
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){81}({domain}[^\,]+)\,""",
    """^([^\,]*\,){17}({activity}[^\,]+)\,""",
    """^([^\,]*\,){8}({additional_info}[^\,]+)\,"""
  ]
  DupFields = [ "host->dest_host" ]
}
```