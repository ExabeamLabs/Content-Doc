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
    """\Wsuser=({src_host}[\w\-.]{1,2000})""",
    """user_email=({user_email}[^@]{1,2000}@[^=]{1,2000}?)\s\w+="""
  ]


}
```