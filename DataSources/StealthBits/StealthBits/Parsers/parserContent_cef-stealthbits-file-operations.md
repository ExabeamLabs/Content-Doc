#### Parser Content
```Java
{
Name = cef-stealthbits-file-operations
  Vendor = StealthBits
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """|STEALTHbits|SBTService|""", """|FileMonitor|""", """Operation=""" ]
  Fields = [
    """\s+({host}[\w.\-]+)\s+CEF:""",
    """\Wrt=({time}\d+\-\d+\-\d+ \d+:\d+:\d+\.\d+)""",
    """\Wsntdom=({domain}[^\s]+)""",
    """\Wsuser=(({domain}[^\\]+)\\)?({user}[^\s\\]+)""",
    """\Wsrc=(|({process_name}.+?))(\s+\w+=|\s*$)""",
    """\Wduser=(|({file_path}({file_parent}.+?)(\\({file_name}[^\\]+?))?))(\s+\w+=|\s*$)""",
    """\Wshost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\WSuccess=\s*(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """\WBlocked=\s*(|({blocked}[^\s]+))\sAttribute""",
    """\WOperation=\s*(|({accesses}.+?))(\s+\w+=|\s*$)"""
  ]
}
```