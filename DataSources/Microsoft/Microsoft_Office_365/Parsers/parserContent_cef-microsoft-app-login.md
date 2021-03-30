#### Parser Content
```Java
{
Name = cef-microsoft-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Log on"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"1":[^=]+?"displayName":"\s*(_splunk_exo|({user_fullname}({user_lastname}[^, "]+)[,\s]+({user_firstname}[^"\(]+?))\s*|({user_email}[^@"]+@({email_domain}[^@"]+?))|({user}[^"\s]+))(\([^"]+\))?"""",
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
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """\Wdvc=(Unknown|Personal|({host}\S+))""",
    """\Wdvchost=(?:Unknown|Personal|({host}[\w\-.]+))\s+\w+=""",
    """act=({activity}[^\s]+)\s+(\w+=|$)""",
    """\Wrt=({time}\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) \S+ Skyformation""",
    """\Wduser=(anonymous|Unknown|email|({user_email}[^@=]+@({email_domain}[^@=]+?))|({user}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|Unknown|email|({user_email}[^@=]+@({email_domain}[^@=]+?))|({user}[^=]+?))(\s+\w+=|\s*$)""",
    """\Woutcome=({outcome}[^\s]+)\s+(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
    """destinationServiceName=({app}[^=]+?)\s+(\w+=|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"description":"({additional_info}[^"]+?)\s*"""",
    """"SourceAccountDisplayName","value":"({user_fullname}({user_firstname}[^\s"]+)\s({user_lastname}[^\s"]+))"""",
    """"SourceAccountUpnName","value":"({user_email}[^@"]+@({email_domain}[^"]+))"""",
    """"SourceComputerDnsName","value":"({src_host}[^"]+)"""",
    """"DestinationComputerDnsName","value":"({dest_host}[^"]+)"""",
    """"DestinationIpAddress","value":"({dest_ip}[a-fA-F\d.:]+)"""",
    """"Protocol","value":"({protocol}[^"]+)""""
  ]

```