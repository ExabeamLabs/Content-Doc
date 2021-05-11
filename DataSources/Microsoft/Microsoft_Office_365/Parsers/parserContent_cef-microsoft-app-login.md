#### Parser Content
```Java
{
Name = cef-microsoft-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Log on"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"1":[^=]+?"displayName":"\s{0,100}(_splunk_exo|({user_fullname}({user_lastname}[^, "]+)[,\s]+({user_firstname}[^"\(]+?))\s{0,100}|({user_email}[^@"]+@({email_domain}[^@"]+?))|({user}[^"\s]+))(\([^"]+\))?"""",
    """device <b>({dest_host}[^<]+)""",
    """"userAgent":";*({user_agent}[^"]+?);*"""",
    """"userAgent":\{"family":"(UNKNOWN|({browser}[^"]+))"""",
    """"operatingSystem":\{"name":"(Unknown|({os}[^"]+))"""",
    """"countryCode":"(--|({country_code}[^"]+))"""",
    """"Upn":"(anonymous|email|({user_email}[^@"]+@({email_domain}[^@"]+?))|({user}[^"\s]+?))"""",
    """"aadTenantId":"(Unknown|Personal|({host}[^",]+))"""",
    """"appName":"({app}[^",]+)""""
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