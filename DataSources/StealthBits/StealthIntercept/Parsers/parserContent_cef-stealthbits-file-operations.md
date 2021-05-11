#### Parser Content
```Java
{
Name = cef-stealthbits-file-operations
  Vendor = StealthBits
  Product = StealthIntercept
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """|STEALTHbits|SBTService|""", """|FileMonitor|""", """Operation=""" ]
  Fields = [
    """\s{1,100}({host}[\w.\-]+)\s{1,100}CEF:""",
    """\Wrt=({time}\d{1,100}\-\d{1,100}\-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})""",
    """\Wsntdom=({domain}[^\s]+)""",
    """\Wsuser=(({domain}[^\\]+)\\)?({user}[^\s\\]+)""",
    """\Wsrc=(|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(|({file_path}({file_parent}.+?)(\\({file_name}[^\\]+?))?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wshost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WSuccess=\s{0,100}(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WBlocked=\s{0,100}(|({blocked}[^\s]+))\sAttribute""",
    """\WOperation=\s{0,100}(|({accesses}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
  ]
}
```