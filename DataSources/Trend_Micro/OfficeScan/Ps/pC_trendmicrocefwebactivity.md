#### Parser Content
```Java
{
Name = trendmicro-cef-web-activity
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Conditions = [ """|Trend Micro|Control Manager|""", """|WB:36|""" ]
  Fields = [
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+[\+\-]\d{1,100}:\d{1,100})""",
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """\Wdvchost=({host}[^\s]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wcs1=({policy}.+?)\s{1,100}\w+=""",
    """\Wrequest=(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?({web_domain}[^\\\/\s:,"]{1,2000})(:\d{1,100})?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s,]{0,2000})?))\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\WdeviceFacility=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=[^\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|re))+)\S+\s{1,100}(\w+=|$)""",
  ]
}
```