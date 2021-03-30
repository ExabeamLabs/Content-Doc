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
      """\Wrt=({time}\w+\s+\d+\s+\d+:\d+:\d+)""",
      """\s({host}[\w\-.]+)\sCEF:\d+\|Bromium, Inc.\|""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d-\d+)""",
      """\Wshost=({src_host}.+?)\s*(\w+=|$)""",
      """\Wsuser=({user}[^@=]+?)\s*(\w+=|$)""",
      """\Wsuser=({user_email}[^@=]+?@[^@=]+?)\s*(\w+=|$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wrequest=({file_uri}.+?)\s*(\w+=|$)""",
      """\Wsproc=({process_name}.+?)\s*(\w+=|$)""",
      """\Wfname=({file_path}.+?)\s*(\w+=|$)""",
      """\Wfname=({file_parent}[^=]+?)[\\\/]+({file_name}[^\\\/=]+?)\s*(\w+=|$)""",
      """\Wmsg=({additional_info}.+?)\s*(\w+=|$)"""
    ]

```