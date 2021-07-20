#### Parser Content
```Java
{
Name = s-skysea-file-access
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",ファイルアクセス," ]
  Fields = [
    """^([^\,]{0,2000}\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """^([^\,]{0,2000}\,){16}({user}[^\,]{1,2000})\,""",
    """exabeam_raw=({host}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]{0,2000}\,){19}({file_path}({file_parent}.*?)({file_name}[^\\.]{1,2000}(\.({file_ext}[^\\.]{1,2000}?))?))\,""",
    """^([^\,]{0,2000}\,){59}({bytes}\d{1,100})\,""",
    """^([^\,]{0,2000}\,){17}({accesses}[^\,]{1,2000})\,"""
  ]
}
```