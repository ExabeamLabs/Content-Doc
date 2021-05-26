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
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """CEF:([^\|]{0,2000}\|){5}({accesses}[^\|]{1,2000})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wrequest=({file_parent}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=[^\s=]{0,2000}?(({domain}[^\\\s\|]{1,2000})\\+)?(system|({user}[^\\\s\|]{1,2000}))\s{1,100}(\w+=|$)""",
    """\WfilePath=(|({file_path}(|({file_parent}[^"]{0,2000}?))[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)))\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """({app}LOGbinder)""",
  ]
}
```