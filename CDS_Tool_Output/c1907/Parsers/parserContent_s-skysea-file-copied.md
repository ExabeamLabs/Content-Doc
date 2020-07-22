#### Parser Content
```Java
{
Name = s-skysea-file-copied
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-write"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",ファイル操作,", ",ファイルコピー," ]
  Fields = [
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){5}(SYSTEM|({user}[^\,]+))\,""",
    """exabeam_raw=({host}[^\,]+)\,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){19}({src_file_name}[^\,]+)\,""",
    """^([^\,]*\,){25}({file_path}({file_parent}.*?)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\,""",
    """^([^\,]*\,){69}({md5}[^\,]+)\,""",
    """^([^\,]*\,){59}({bytes}\d+)\,"""
  ]
}
```