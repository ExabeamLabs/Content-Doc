#### Parser Content
```Java
{
Name = n-forwarded-cef-trendmicro-web-activity-1
  Conditions = [ "|McAfee|ESM", "283-3264693095" ]

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
    """\WnitroURL=(\w+:\/\/)?[^=]{0,2000}?({top_domain}[^\s.]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\s|\/)""",
    """\Wsntdom=[^=]{0,2000}?({top_domain}[^\s.]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)\s""",
  
}
```