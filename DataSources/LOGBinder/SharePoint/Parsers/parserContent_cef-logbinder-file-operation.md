#### Parser Content
```Java
{
Name = cef-logbinder-file-operation
  Vendor = LOGBinder
  Product = SharePoint
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions= [ """CEF:""", """|LOGbinder|""", """ request=""", """ filePath=""", """ fname=""" ]
  Fields = [
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """CEF:([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wrequest=({file_parent}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=[^\s=]*?(({domain}[^\\\s\|]+)\\+)?(system|({user}[^\\\s\|]+))\s{1,100}(\w+=|$)""",
    """\WfilePath=(|({file_path}(|({file_parent}[^"]*?))[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """({app}LOGbinder)""",
  ]
}
```