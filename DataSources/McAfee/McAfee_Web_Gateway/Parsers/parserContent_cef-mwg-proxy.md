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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wrt=({time}\d{1,100})""",
    """\WcategoryOutcome=\/?({action}[^\/]+?)\s{0,100}([\w\.]+=|$)""",
    """\Wdvc=({host}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wapp=({protocol}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wsuser=({user}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WfileType=({mime}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WrequestMethod=({method}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wrequest=({url}(?:\w+:\/\/)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\/\s=]+))({uri_path}\/.*?)?)(\s{1,100}[\w\.]+=|\s{0,100}$)""",
    """\WdestinationDnsDomain=({top_domain}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WrequestClientApplication=({user_agent}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WrequestClientApplication=Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wreason=({failure_reason}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wrequest=({full_url}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wrequest=(?:-|\w+:\/+[^\/\s=]+)({uri_path}\/[^?\s]+)""",
    """\Wrequest=(-|([^?]+({uri_query}\?[^\s"]+)))\s{0,100}([\w\.]+=|$)""",
    """\WrequestContex=({uri_query}.+?)\s{0,100}([\w\.]+=|$)""",
    """flexString1Label=FQDN.+?\WflexString1=({web_domain}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WflexString1=({web_domain}.+?)\s{1,100}(?:flexString1Label=FQDN|[\w\.]+=.+?flexString1Label=FQDN)""",
    """flexString2Label=Domain.+?\WflexString2=({top_domain}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WflexString2=({top_domain}.+?)\s{1,100}(?:flexString2Label=Domain|[\w\.]+=.+?flexString2Label=Domain)""",
    """flexNumber1Label=Port.+?\WflexNumber1=({dest_port}\d{1,100})""",
    """\WflexNumber1=({dest_port}\d{1,100})\s{1,100}(?:flexNumber1Label=Port|[\w\.]+=.+?flexNumber1Label=Port)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Win=({bytes_out}\d{1,100})""",
    """\Wout=({bytes_in}\d{1,100})""",
    """cs6Label=Categories.+?\Wcs6=({category}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wcs6=({category}.+?)\s{1,100}(?:cs6Label=Categories|[\w\.]+=.+?cs6Label=Categories)""",
    """cs6Label=Reputation.+?\Wcs6=({risk_level}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wcs6=({risk_level}.+?)\s{1,100}(?:cs6Label=Reputation|[\w\.]+=.+?cs6Label=Reputation)""",
    """flexString2Label=Site Categories.+?\sflexString2=({category}.+?)\s{0,100}([\w\.]+=|$)""",
    """\WflexString2=({category}.+?)\s{1,100}(?:flexString2Label=Site Categories|[\w\.]+=.+?flexString2Label=Site Categories)""",
    """cs5Label=Block Reason.+?\Wcs5=({action}.+?)\s{0,100}([\w\.]+=|$)""",
    """\Wcs5=({action}.+?)\s{1,100}(?:cs5Label=Block Reason|[\w\.]+=.+?cs5Label=Block Reason)""",
    """\Wad\.Rep__level=({risk_level}.+?)\s{0,100}([\w\.]+=|$)""",
    """([^\|]*\|){4}({result_code}[^\|]+)""",
  ]
}
```