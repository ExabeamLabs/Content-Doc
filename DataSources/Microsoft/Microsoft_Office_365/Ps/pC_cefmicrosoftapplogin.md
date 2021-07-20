#### Parser Content
```Java
{
Name = cef-microsoft-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Log on"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"1":[^=]{1,2000}?"displayName":"\s{0,100}(_splunk_exo|({user_fullname}({user_lastname}[^, "]{1,2000})[,\s]{1,2000}({user_firstname}[^"\(]{1,2000}?))\s{0,100}|({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}?))|({user}[^"\s]{1,2000}))(\([^"]{1,2000}\))?"""",
    """device <b>({dest_host}[^<]{1,2000})""",
    """"userAgent":";*({user_agent}[^"]{1,2000}?);*"""",
    """"userAgent":\{"family":"(UNKNOWN|({browser}[^"]{1,2000}))"""",
    """"operatingSystem":\{"name":"(Unknown|({os}[^"]{1,2000}))"""",
    """"countryCode":"(--|({country_code}[^"]{1,2000}))"""",
    """"Upn":"(anonymous|email|({user_email}[^@"]{1,2000}@({email_domain}[^@"]{1,2000}?))|({user}[^"\s]{1,2000}?))"""",
    """"aadTenantId":"(Unknown|Personal|({host}[^",]{1,2000}))"""",
    """"appName":"({app}[^",]{1,2000})""""
  ]
}
cef-azure-app-activity-1 = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """\Wdvc=(Unknown|Personal|({host}\S+))""",
    """\Wdvchost=(?:Unknown|Personal|({host}[\w\-.]{1,2000}))\s{1,100}\w+=""",
    """act=({activity}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) \S+ Skyformation""",
    """\Wduser=(anonymous|Unknown|email|({user_email}[^@=]{1,2000}@({email_domain}[^@=]{1,2000}?))|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|Unknown|email|({user_email}[^@=]{1,2000}@({email_domain}[^@=]{1,2000}?))|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=({outcome}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
    """destinationServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"description":"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"SourceAccountDisplayName","value":"({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^\s"]{1,2000}))"""",
    """"SourceAccountUpnName","value":"({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"SourceComputerDnsName","value":"({src_host}[^"]{1,2000})"""",
    """"DestinationComputerDnsName","value":"({dest_host}[^"]{1,2000})"""",
    """"DestinationIpAddress","value":"({dest_ip}[a-fA-F\d.:]{1,2000})"""",
    """"Protocol","value":"({protocol}[^"]{1,2000})""""
  ]

```