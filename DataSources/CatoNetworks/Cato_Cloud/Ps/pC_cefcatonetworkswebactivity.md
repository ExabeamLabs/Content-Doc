#### Parser Content
```Java
{
Name = cef-catonetworks-web-activity
  Vendor = CatoNetworks
  Product = Cato Cloud
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "EEE MMM dd HH:mm:ss Z yyyy"
  Conditions = [ """CEF:""", """|CatoNetworks|""", """internalType=SECURITY""", """ act=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\w+\s{1,100}\d\d\d\d)""",
    """\Wcs1=({src_country}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wcs2=(-|({dest_country}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wdproc=({categories}({category}[^,;\=]{1,2000})[^\=]{0,2000}?)\s{1,100}(\w+=|$)""",
    """\Wact=({outcome}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """destinationDnsDomain=({web_domain}[^=]{1,2000}?)\s\w+=""",
    """\Wshost=({user_fullname}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WdestinationDnsDomain=[^\=\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone))+)\s{1,100}(\w+=|$)""",
    """\Wsuser=({src_host}[\w\-.]{1,2000})""",
    """user_email=({user_email}[^@]{1,2000}@[^=]{1,2000}?)\s\w+="""
  ]


}
```