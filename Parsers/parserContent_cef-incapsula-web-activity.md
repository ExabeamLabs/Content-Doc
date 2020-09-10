#### Parser Content
```Java
{
Name = cef-incapsula-web-activity
  Vendor = Imperva
  Product = Incapsula
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Incapsula|SIEMintegration|""", """|DDoS|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """\Wstart=({time}\d+)""",
    """\Wsrc=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wact=({action}.+?)\s+(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s+(\w+=|$)""",
    """\Wref=({referrer}.+?)\s+(\w+=|$)""",
    """\WsourceServiceName=({web_domain}([^\s]+\.)?({top_domain}[^\s]+\.[^\s]+)?)\s""",
    """\WrequestClientApplication=({user_agent}.+?)\s+(\w+=|$)""",
    """\Wccode=({country_code}.+?)\s+(\w+=|$)""",
    """\WCustomer=({customer}.+?)\s+(\w+=|$)""",
    """\Wrequest=({full_url}.+?)\s+(\w+=|$)""",
    """\WrequestMethod=({method}.+?)\s+(\w+=|$)""",
    """\Wdproc=({category}.+?)\s+(\w+=|$)"""
  ]
}
```