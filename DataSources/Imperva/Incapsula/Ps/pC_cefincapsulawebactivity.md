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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\Wstart=({time}\d{1,100})""",
    """\Wsrc=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wact=({action}.+?)\s{1,100}(\w+=|$)""",
    """\Wapp=({protocol}.+?)\s{1,100}(\w+=|$)""",
    """\Wref=({referrer}.+?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName =({web_domain}([^\s]{1,2000}\.)?({top_domain}[^\s]{1,2000}\.[^\s]{1,2000})?)\s""",
    """\WrequestClientApplication=({user_agent}.+?)\s{1,100}(\w+=|$)""",
    """\Wccode=({country_code}.+?)\s{1,100}(\w+=|$)""",
    """\WCustomer=({customer}.+?)\s{1,100}(\w+=|$)""",
    """\Wrequest=({full_url}.+?)\s{1,100}(\w+=|$)""",
    """\WrequestMethod=({method}.+?)\s{1,100}(\w+=|$)""",
    """\Wdproc=({category}.+?)\s{1,100}(\w+=|$)"""
  ]


}
```