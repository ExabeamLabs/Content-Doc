#### Parser Content
```Java
{
Name = s-skysea-file-access
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",????????????????????????," ]
  Fields = [
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){16}({user}[^\,]+)\,""",
    """exabeam_raw=({host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){19}({file_path}({file_parent}.*?)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\,""",
    """^([^\,]*\,){59}({bytes}\d+)\,""",
    """^([^\,]*\,){17}({accesses}[^\,]+)\,"""
  ]
}
```