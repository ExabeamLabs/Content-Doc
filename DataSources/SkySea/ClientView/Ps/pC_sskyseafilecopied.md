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
    """exabeam_raw=({host}[^\,]{1,2000})\,""",
    """(^|,)"?({host}[^,]{1,2000})"?,([^,]{0,2000},){6}({time}\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d),ファイル操作""",
    """(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]{1,2000})),([^,]{0,2000},){6}ファイル操作""",
    """(SYSTEM|({user}[^,]{1,2000})),([^,]{0,2000},){4}ファイル操作""",
    """,({activity}ファイルコピー),""",
    """,ファイルコピー,[^,]{0,2000},({src_file_name}[^,]{1,2000}),([^,]{0,2000},){5}({file_path}({file_parent}.*?)({file_name}[^\\.,]{1,2000}(\.({file_ext}[^\\.,]{1,2000}?))?)),""",
    """,ファイルコピー,([^,]{0,2000},){51}({md5}[^,]{1,2000}),""",
    """,ファイルコピー,([^,]{0,2000},){64}({bytes}[^,]{1,2000}),""",

  ]
}
```