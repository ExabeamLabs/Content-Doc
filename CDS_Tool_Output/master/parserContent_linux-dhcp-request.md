#### Parser Content
```Java
{
Name = linux-dhcp-request
  Vendor = Linux
  Product = Linux DHCP
  Lms = Direct
  DataType = "dhcp"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ DHCPREQUEST for """ , """ from """, """ via """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """({host}[a-fA-F\d\.:]+)\s+DHCPREQUEST for ({dest_ip}[a-fA-F\d\.:]+)\s.*?from ({dest_mac}[a-fA-F\d\.:]+)(\s\(({dest_host}\S+)\))?( via ({dest_interface}\S+?):?\s)?""",
  ]
  DupFields = [ "host->auth_server" ]
}

{
  Name = entrust-identityguard-auth-successful
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] User """ , """ successfully authenticated a challenge.""", """ Authentication Type: """, """ Remote Address: """ ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d+\])""",
    """\] User (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+))\s""",
    """Authentication Type: ({auth_method}[^,]+),""",
    """Application Name: ({app}[^,]+),""",
    """Remote Address: ({src_ip}[a-fA-F\d\.:]+)""",
    """({additional_info}Token Used: [^,]+)""",
  ]
}

{
  Name = entrust-identityguard-auth-failed-2
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] User """ , """ failed authentication.""", """ Authentication Type: """, """ Application Name: """, """ Remote Address: """ ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d+\])""",
    """ User (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+)) failed authentication""",
    """Authentication Type: ({auth_method}[^,]+),""",
    """Application Name: ({app}[^,]+),""",
    """Remote Address: ({src_ip}[a-fA-F\d\.:]+)""",
  ]
}

{
  Name = entrust-identityguard-auth-failed-3
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] Failed authentication for user """, """Invalid response to a challenge.""", """ authentication attempts remaining.""" ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d+\])""",
    """ user (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+))\. """,
    """({additional_info}Invalid response to a challenge.[^\.]+)""",
  ]
}

{
  Name = entrust-identityguard-account-lockout
  Vendor = Entrust
  Product = IdentityGuard
  Lms = Direct
  DataType = "account-lockout"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ Maximum authentication attempts exceeded. """ , """ is locked.""" ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\[({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\]|,\]|,\d+\])""",
    """({event_description}Maximum authentication.+?is locked.)""",
    """User (({user_email}[^\@\s]+@[^\s]+)|(({domain}[^\\\/]+)[\\\/]+)?({user}[^\s]+)) is locked.""",
  ]
}

{
 Name = zebra-wlm-ssh-failed
 Vendor = Extreme Networks
 Product = Zebra wireless LAN management
 Lms = Direct
 DataType = "failed-logon"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = [ """%25SYSTEM-3-LOGIN_FAIL:""", """Log-in failed""" ]
 Fields =[
   """({time}\d+-\d+-\d+T\d+:\d+:\d+).\d[^\s]+\s+({host}[^\s]+)\s+({event_code}[^:]+):\s+Log-in ({outcome}failed) for user '({user}[^']+)'\s+from '({protocol}[^']+)*"""
  ]
}
${AirWatchParserTemplates.airwatch-auth-activity}{
  Name = airwatch-authentication
  DataType = "authentication-successful" 
  Conditions = [ """AirWatch""", """Event Category:"Authentication"""", """Event:""""]
  Fields = ${AirWatchParserTemplates.airwatch-auth-activity.Fields}[]
  DupFields = ["event_type->auth_type"]
}
${AirWatchParserTemplates.airwatch-auth-activity}{
  Name = airwatch-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """AirWatch""", """Event Category:"Login"""", """Event:""""]
}
${AirWatchParserTemplates.airwatch-auth-activity}{
  Name = airwatch-security-alerts
  DataType = "security-alerts"
  Conditions = [ """AirWatch""", """Event Category:"""", """Event:"""" ]

}

{
  Name = anywhere365-app-activity
  Conditions = [""" CallReceivedOnEndpoint: """]
  Vendor = Anywhere365
  Product = Anywhere365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\s({log_id}\w+-\w+-\w+-\w+-\w+)\s""",
    """CallReceivedOnEndpoint:\s'sip:({recipient}[^@]+[^\.]+\.[^,\s;']+)""",
  ]
}
```