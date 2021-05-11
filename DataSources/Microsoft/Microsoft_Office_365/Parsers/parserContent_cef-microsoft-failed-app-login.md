#### Parser Content
```Java
{
Name = cef-microsoft-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Failed log on """ ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"description":"Failed log on \(({failure_reason}[^\)]+)""",
    """"failedUserData":\{"userName":"(({user_email}[^@"]+@[^\.]+\.[^"]+)|({user}[^"]+))"""",
    """"operatingSystem":\{"name":"((?i)Unknown|({os}[^"]+))"""",
    """"userAgent":";?({user_agent}[^"]+?)[;]*"""",
  ]
}
cef-azure-app-activity-1 = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w.\-]+)""",
    """\Wdvc=(Unknown|Personal|({host}\S+))""",
    """\Wdvchost=(?:Unknown|Personal|({host}[\w\-.]+))\s{1,100}\w+=""",
    """act=({activity}[^\s]+)\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) \S+ Skyformation""",
    """\Wduser=(anonymous|Unknown|email|({user_email}[^@=]+@({email_domain}[^@=]+?))|({user}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|Unknown|email|({user_email}[^@=]+@({email_domain}[^@=]+?))|({user}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=({outcome}[^\s]+)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
    """destinationServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"description":"({additional_info}[^"]+?)\s{0,100}"""",
    """"SourceAccountDisplayName","value":"({user_fullname}({user_firstname}[^\s"]+)\s({user_lastname}[^\s"]+))"""",
    """"SourceAccountUpnName","value":"({user_email}[^@"]+@({email_domain}[^"]+))"""",
    """"SourceComputerDnsName","value":"({src_host}[^"]+)"""",
    """"DestinationComputerDnsName","value":"({dest_host}[^"]+)"""",
    """"DestinationIpAddress","value":"({dest_ip}[a-fA-F\d.:]+)"""",
    """"Protocol","value":"({protocol}[^"]+)""""
  ]

```