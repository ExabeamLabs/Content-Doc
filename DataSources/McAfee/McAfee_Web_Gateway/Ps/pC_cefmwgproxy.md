#### Parser Content
```Java
{
Name = cef-mwg-proxy
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|McAfee|Web Gateway|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\w{1,3} \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wrt=({time}\d{1,100})""",
    """\WcategoryOutcome=\/?({action}[^\/]{1,2000}?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wdvc=({host}[^=]{1,2000}?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wapp=({protocol}[^=]{1,2000}?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wsuser=(-|\([^\)]{1,2000}\)|({user}[^=]{1,2000}?))\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WfileType=({mime}[^=]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\WrequestMethod=({method}[^=]{1,2000}?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrequest=({url}(?:\w+:\/\/)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\/\s=]{1,2000}))({uri_path}\/.*?)?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\Wrequest=([^=]{0,2000}?)({top_domain}[^\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))[^\s]{0,2000}(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\WrequestClientApplication=Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wreason=({failure_reason}[^=]{1,2000}?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wrequest=({full_url}[^\s=]{1,2000}?({uri_path}\/[^?\s]{1,2000}?)?({uri_query}\?[^\s"]{1,2000})?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\WflexNumber1=({dest_port}\d{1,100})\s{1,100}(flexNumber1Label=Port|[\w\.]{1,2000}=.+?flexNumber1Label=Port)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Win=({bytes_out}\d{1,100})""",
    """\Wout=({bytes_in}\d{1,100})""",
    """\Wcs6=({category}[^=]{1,2000}?)\s{1,100}(?:cs6Label=Categories|[\w\.]{1,2000}=.+?cs6Label=Categories)""",
    """\WflexString2=({category}[^=]{1,2000}?)\s{1,100}(?:flexString2Label=Site Categories|[\w\.]{1,2000}=.+?flexString2Label=Site Categories)""",
    """\Wcs5=({action}[^=]{1,2000}?)\s{1,100}(?:cs5Label=Block Reason|[\w\.]{1,2000}=.+?cs5Label=Block Reason)""",
    """\|McAfee\|Web Gateway\|[^\|]{0,2000}\|({result_code}[^\|]{1,2000})""",
  ]


}
```