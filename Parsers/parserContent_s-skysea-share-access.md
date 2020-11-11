#### Parser Content
```Java
{
Name = s-skysea-share-access
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "share-access"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",??????????????????," ]
  Fields = [
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){5}({user}[^\,]+)\,""",
    """exabeam_raw=({host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){8}({access_type}[^\,]+)\,""",
    """^([^\,]*\,){11}({file_path}({file_parent}([^\,]+\\)?)({file_name}[^\,]+))\,"""
  ]
}
```