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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wrt=({time}\d+)""",
    """\WcategoryOutcome=\/?({action}[^\/]+?)\s*([\w\.]+=|$)""",
    """\Wdvc=({host}.+?)\s*([\w\.]+=|$)""",
    """\Wapp=({protocol}.+?)\s*([\w\.]+=|$)""",
    """\Wsuser=({user}.+?)\s*([\w\.]+=|$)""",
    """\WfileType=({mime}.+?)\s*([\w\.]+=|$)""",
    """\WrequestMethod=({method}.+?)\s*([\w\.]+=|$)""",
    """\Wrequest=({url}(?:\w+:\/\/)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\/\s=]+))({uri_path}\/.*?)?)(\s+[\w\.]+=|\s*$)""",
    """\WdestinationDnsDomain=({top_domain}.+?)\s*([\w\.]+=|$)""",
    """\WrequestClientApplication=({user_agent}.+?)\s*([\w\.]+=|$)""",
    """\WrequestClientApplication=Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wreason=({failure_reason}.+?)\s*([\w\.]+=|$)""",
    """\Wrequest=({full_url}.+?)\s*([\w\.]+=|$)""",
    """\Wrequest=(?:-|\w+:\/+[^\/\s=]+)({uri_path}\/[^?\s]+)""",
    """\Wrequest=(-|([^?]+({uri_query}\?[^\s"]+)))\s*([\w\.]+=|$)""",
    """\WrequestContex=({uri_query}.+?)\s*([\w\.]+=|$)""",
    """flexString1Label=FQDN.+?\WflexString1=({web_domain}.+?)\s*([\w\.]+=|$)""",
    """\WflexString1=({web_domain}.+?)\s+(?:flexString1Label=FQDN|[\w\.]+=.+?flexString1Label=FQDN)""",
    """flexString2Label=Domain.+?\WflexString2=({top_domain}.+?)\s*([\w\.]+=|$)""",
    """\WflexString2=({top_domain}.+?)\s+(?:flexString2Label=Domain|[\w\.]+=.+?flexString2Label=Domain)""",
    """flexNumber1Label=Port.+?\WflexNumber1=({dest_port}\d+)""",
    """\WflexNumber1=({dest_port}\d+)\s+(?:flexNumber1Label=Port|[\w\.]+=.+?flexNumber1Label=Port)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Win=({bytes_out}\d+)""",
    """\Wout=({bytes_in}\d+)""",
    """cs6Label=Categories.+?\Wcs6=({category}.+?)\s*([\w\.]+=|$)""",
    """\Wcs6=({category}.+?)\s+(?:cs6Label=Categories|[\w\.]+=.+?cs6Label=Categories)""",
    """cs6Label=Reputation.+?\Wcs6=({risk_level}.+?)\s*([\w\.]+=|$)""",
    """\Wcs6=({risk_level}.+?)\s+(?:cs6Label=Reputation|[\w\.]+=.+?cs6Label=Reputation)""",
    """flexString2Label=Site Categories.+?\sflexString2=({category}.+?)\s*([\w\.]+=|$)""",
    """\WflexString2=({category}.+?)\s+(?:flexString2Label=Site Categories|[\w\.]+=.+?flexString2Label=Site Categories)""",
    """cs5Label=Block Reason.+?\Wcs5=({action}.+?)\s*([\w\.]+=|$)""",
    """\Wcs5=({action}.+?)\s+(?:cs5Label=Block Reason|[\w\.]+=.+?cs5Label=Block Reason)""",
    """\Wad\.Rep__level=({risk_level}.+?)\s*([\w\.]+=|$)""",
    """([^\|]*\|){4}({result_code}[^\|]+)""",
  ]
}
```