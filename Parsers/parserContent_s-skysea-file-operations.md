#### Parser Content
```Java
{
Name = s-skysea-file-operations
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "file-operations"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",??????????????????," ]
  Fields = [
    """^([^\,]*\,){7}({time}\d+\/\d+\/\d+ \d+:\d+:\d+)""",
    """^([^\,]*\,){5}(SYSTEM|NETWORK SERVICE|({user}[^\,]+))\,""",
    """({host}[\w\-.]+),\d+,""",
    """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]*\,){19}({file_path}({file_parent}[^,]*?)({file_name}[^\\.,]+(\.({file_ext}[^\\.,]+?))?))\,""",
    """^([^\,]*\,){17}({accesses}[^\,]+)\,""",
    """^([^\,]*\,){69}({md5}[^\,]+)\,""",
    """^([^\,]*\,){82}({bytes}\d+)\,"""
  ]
}
```