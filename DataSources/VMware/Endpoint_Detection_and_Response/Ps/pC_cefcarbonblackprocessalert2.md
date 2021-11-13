#### Parser Content
```Java
{
Name = cef-carbonblack-process-alert-2
  Conditions = [ """CEF:""", """|CarbonBlack|Response|""", """alert.watchlist.hit.query.process""" ]

cef-carbonblack-process-alert = {
  Vendor = VMware
  Product = Endpoint Detection and Response 
  Lms = ArcSight
  DataType = "process-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """({host}[\w.\-]{1,2000}):\s{1,100}CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
    """\Wend=({time}\d{1,100})""",
    """\Wcs3=(|({command_line}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs5=(|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wshost=(|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WfilePath=({process}({directory}[^=]{0,2000}?[\\\/]{1,2000})?[^\\\/=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WfileHash=(|({md5}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcs2=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn2=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  
}
```