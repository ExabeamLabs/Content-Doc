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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\w+\s+\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\w+\s+\d\d\d\d)""",
    """\Wcs1=({src_country}.+?)\s+(\w+=|$)""",
    """\Wcs2=({dest_country}.+?)\s+(\w+=|$)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wdproc=({categories}({category}[^,;\=]+)[^\=]*?)\s+(\w+=|$)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wdhost=({web_domain}.+?)\s+(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s+(\w+=|$)""",
    """\Wdhost=[^\=\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|am|be|bid|blog|bot|ch|cloud|ec|goog|hosting|il|im|la|link|live|ly|market|media|mobi|ms|network|ninja|pe|ph|place|pro|se|site|space|stream|tech|to|top|ua|vc|video|watch|ws|wtf|xyz|zone))+)\s+(\w+=|$)""",
    """\Wsuser=({src_host}[\w\-.]+)""",
  ]
}
```