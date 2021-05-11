#### Parser Content
```Java
{
Name = cef-bromium-file-read
  Vendor = Bromium
  Product = Bromium Secure Platform
  Conditions = [ """|Bromium, Inc.|vSentry|""", """suser=""", """|vSentry isolated a file download|""" ]
  Fields = ${BromiumParserTemplates.cef-bromium-file-operations.Fields} [
    """({accesses}download)"""
  ]
}
cef-bromium-file-operations = {
    Vendor = Bromium
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Fields = [
      """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
      """\s({host}[\w\-.]+)\sCEF:\d{1,100}\|Bromium, Inc.\|""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d-\d{1,100})""",
      """\Wshost=({src_host}.+?)\s{0,100}(\w+=|$)""",
      """\Wsuser=({user}[^@=]+?)\s{0,100}(\w+=|$)""",
      """\Wsuser=({user_email}[^@=]+?@[^@=]+?)\s{0,100}(\w+=|$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wrequest=({file_uri}.+?)\s{0,100}(\w+=|$)""",
      """\Wsproc=({process_name}.+?)\s{0,100}(\w+=|$)""",
      """\Wfname=({file_path}.+?)\s{0,100}(\w+=|$)""",
      """\Wfname=({file_parent}[^=]+?)[\\\/]+({file_name}[^\\\/=]+?)\s{0,100}(\w+=|$)""",
      """\Wmsg=({additional_info}.+?)\s{0,100}(\w+=|$)"""
    ]

```