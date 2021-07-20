#### Parser Content
```Java
{
Name = s-skysea-share-access
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "share-access"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",フォルダ共有," ]
  Fields = [
    """^([^\,]{0,2000}\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """^([^\,]{0,2000}\,){5}({user}[^\,]{1,2000})\,""",
    """exabeam_raw=({host}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
    """^([^\,]{0,2000}\,){8}({access_type}[^\,]{1,2000})\,""",
    """^([^\,]{0,2000}\,){11}({file_path}({file_parent}([^\,]{1,2000}\\)?)({file_name}[^\,]{1,2000}))\,"""
  ]
}
```