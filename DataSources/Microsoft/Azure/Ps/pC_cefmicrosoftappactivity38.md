#### Parser Content
```Java
{
Name = cef-microsoft-app-activity-38
  DataType = "app-activity"
  Conditions = [ """destinationServiceName =Office 365""", """LDAP query""", """Run command:""" ]

cef-azure-app-activity-1 = {
  Vendor = Microsoft
  Product = Azure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """\Wdvc=(Unknown|Personal|({host}\S+))""",
    """\Wdvchost=(?:Unknown|Personal|({host}[\w\-.]{1,2000}))\s{1,100}\w+=""",
    """act=({activity}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) \S+ """,
    """\Wduser=(anonymous|Unknown|email|({user_email}[^@=]{1,2000}@({email_domain}[^@=]{1,2000}?))|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(anonymous|Unknown|email|({user_email}[^@=]{1,2000}@({email_domain}[^@=]{1,2000}?))|({user}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woutcome=({outcome}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){2}({app}[^\|]{1,2000})""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"description":"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"SourceAccountDisplayName","value":"({user_fullname}({user_firstname}[^\s"]{1,2000})\s({user_lastname}[^\s"]{1,2000}))"""",
    """"SourceAccountUpnName","value":"({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"SourceComputerDnsName","value":"({src_host}[^"]{1,2000})"""",
    """"DestinationComputerDnsName","value":"({dest_host}[^"]{1,2000})"""",
    """"DestinationIpAddress","value":"({dest_ip}[a-fA-F\d.:]{1,2000})"""",
    """"Protocol","value":"({protocol}[^"]{1,2000})""""
  
}
```