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
    """exabeam_raw=({host}[^\,]+)\,""",
    """(^|,)"?({host}[^,]+)"?,([^,]*,){6}({time}\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d),ファイル操作""",
    """(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]+)),([^,]*,){6}ファイル操作""",
    """(SYSTEM|({user}[^,]+)),([^,]*,){4}ファイル操作""",
    """,({activity}ファイルコピー),""",
    """,ファイルコピー,[^,]*,({src_file_name}[^,]+),([^,]*,){5}({file_path}({file_parent}.*?)({file_name}[^\\.,]+(\.({file_ext}[^\\.,]+?))?)),""",
    """,ファイルコピー,([^,]*,){51}({md5}[^,]+),""",
    """,ファイルコピー,([^,]*,){64}({bytes}[^,]+),""",

  ]
}
```