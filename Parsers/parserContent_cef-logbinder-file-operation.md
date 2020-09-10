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
    """({host}[\w\-.]+)\s+CEF:""",
    """CEF:([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wrequest=({file_parent}.+?)\s+(\w+=|$)""",
    """\Wduser=[^\s=]*?(({domain}[^\\\s\|]+)\\+)?(system|({user}[^\\\s\|]+))\s+(\w+=|$)""",
    """\WfilePath=(|({file_path}(|({file_parent}[^"]*?))[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """({app}LOGbinder)""",
  ]
}
```