#### Parser Content
```Java
{
Name = s-zscaler-dlp-alert-1
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """dlpengine=""", """dlpdictionaries=""", """event_id=""", """url=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s""",
    """\saction=({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sprotocol=({protocol}[^\s]{1,2000})\s{1,100}\w+=""",
    """\sClientIP=({src_ip}[a-fA-F\.\d:]{1,2000})""",
    """\sserverip=(?:0.0.0.0|({dest_ip}[a-fA-F\.\d:]{1,2000}))""",
    """\suseragent=({user_agent}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\suser=(({user_email}[^\s@]{1,2000}@[^\s\.]{1,2000}\.[^\s=]{1,2000}?)|({user}[^\s@=]{1,2000}?))\s{1,100}\w+=""",
    """\shostname=({host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdlpengine=({alert_name}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\surl=({target}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """responsesize=({bytes_in}\d{1,20})""",
    """requestsize==({bytes_out}\d{1,20})""",
    """requestmethod=({method}[^\s]{1,2000})""",
    """\sodevicehostname=({src_host}[^\s]{1,2000})""",
    """\sodeviceowner=(NA|({device_owner}[^\s]{1,2000}))"""
  ]


}
```