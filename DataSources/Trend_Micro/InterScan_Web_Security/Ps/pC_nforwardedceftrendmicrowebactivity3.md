#### Parser Content
```Java
{
Name = n-forwarded-cef-trendmicro-web-activity-3
  Conditions = [ "|McAfee|ESM", "283-2294663204" ]

n-forwarded-cef-trendmicro-web-activity = {
  Vendor = Trend Micro
  Product = InterScan Web Security
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\WnitroCategory=({category}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=({action}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WnitroMethod=({method}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WnitroURL=({full_url}(\w+:\/\/)?(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)({uri_query}\?.+?)?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsntdom=({web_domain}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WnitroRequest_Type=({protocol}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  
}
```