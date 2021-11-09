#### Parser Content
```Java
{
Name = s-zscaler-web-activity-5
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-ddHH:mm:ss"
  Conditions = [ """dlpidentifier=""", """dlpdictionaries=""", """dlpengine=""", """url=""", """appclass=""", """appname=""", """clientpublicIP=""", """refererURL=""" ]
  Fields =[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\d\d:\d{1,100}:\d{1,100})\s{1,100}(\w+=|$)""",
    """urlcategory=(Miscellaneous or Unknown|({category}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\saction=({action}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\sprotocol=({protocol}[^=]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\sserverip=(?:0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\srequestmethod=(NA|({method}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\srefererURL="{0,20}(?:None|({referrer}[^\s]{1,2000}?))\/?"{0,20}\s{0,100}(\w+=|$)""",
    """\suseragent=(Unknown|({user_agent}[^=]{1,2000}?))\s{0,100}(\w+=|$)""",
    """\sstatus=({result_code}\d{1,100})""",
    """\sclientpublicIP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\sClientIP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\suser=((({domain}[\w.\-]{1,2000})->[^=]{1,2000}?)|({user_email}[^@]{1,2000}@[^\s=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\surl="{0,20}(?:None|({full_url}[^\s"]{1,2000}))"{0,20}\s{0,100}(\w+=|$)""",
    """\surl="{0,20}(\w+:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s"]{1,2000})""",
    """\surl="{0,20}(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s"]{1,2000})""",
    """\shostname=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({web_domain}\S+))""",
    """\sappname=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
  ]
}
}
```