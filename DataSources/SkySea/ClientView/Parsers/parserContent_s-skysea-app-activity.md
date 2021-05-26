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
    """exabeam_raw=({host}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){2}({src_host}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]{0,2000}\,){5}({user}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """^([^\,]{0,2000}\,){81}({domain}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){17}({activity}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){8}({additional_info}[^\,]{1,2000})\,"""
  ]
  DupFields = [ "host->dest_host" ]
}
```