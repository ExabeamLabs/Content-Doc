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
    """\Wrt=({time}\d{1,100})""",
    """\WcategoryOutcome=\/?({action}[^\/]{1,2000}?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wdvc=({host}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wapp=({protocol}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wsuser=({user}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WfileType=({mime}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WrequestMethod=({method}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wrequest=({url}(?:\w+:\/\/)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\/\s=]{1,2000}))({uri_path}\/.*?)?)(\s{1,100}[\w\.]{1,2000}=|\s{0,100}$)""",
    """\WdestinationDnsDomain=({top_domain}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WrequestClientApplication=({user_agent}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WrequestClientApplication=Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wreason=({failure_reason}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wrequest=({full_url}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wrequest=(?:-|\w+:\/+[^\/\s=]{1,2000})({uri_path}\/[^?\s]{1,2000})""",
    """\Wrequest=(-|([^?]{1,2000}({uri_query}\?[^\s"]{1,2000})))\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WrequestContex=({uri_query}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """flexString1Label=FQDN.+?\WflexString1=({web_domain}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WflexString1=({web_domain}.+?)\s{1,100}(?:flexString1Label=FQDN|[\w\.]{1,2000}=.+?flexString1Label=FQDN)""",
    """flexString2Label=Domain.+?\WflexString2=({top_domain}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WflexString2=({top_domain}.+?)\s{1,100}(?:flexString2Label=Domain|[\w\.]{1,2000}=.+?flexString2Label=Domain)""",
    """flexNumber1Label=Port.+?\WflexNumber1=({dest_port}\d{1,100})""",
    """\WflexNumber1=({dest_port}\d{1,100})\s{1,100}(?:flexNumber1Label=Port|[\w\.]{1,2000}=.+?flexNumber1Label=Port)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Win=({bytes_out}\d{1,100})""",
    """\Wout=({bytes_in}\d{1,100})""",
    """cs6Label=Categories.+?\Wcs6=({category}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wcs6=({category}.+?)\s{1,100}(?:cs6Label=Categories|[\w\.]{1,2000}=.+?cs6Label=Categories)""",
    """cs6Label=Reputation.+?\Wcs6=({risk_level}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wcs6=({risk_level}.+?)\s{1,100}(?:cs6Label=Reputation|[\w\.]{1,2000}=.+?cs6Label=Reputation)""",
    """flexString2Label=Site Categories.+?\sflexString2=({category}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\WflexString2=({category}.+?)\s{1,100}(?:flexString2Label=Site Categories|[\w\.]{1,2000}=.+?flexString2Label=Site Categories)""",
    """cs5Label=Block Reason.+?\Wcs5=({action}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """\Wcs5=({action}.+?)\s{1,100}(?:cs5Label=Block Reason|[\w\.]{1,2000}=.+?cs5Label=Block Reason)""",
    """\Wad\.Rep__level=({risk_level}.+?)\s{0,100}([\w\.]{1,2000}=|$)""",
    """([^\|]{0,2000}\|){4}({result_code}[^\|]{1,2000})""",
  ]
}
```