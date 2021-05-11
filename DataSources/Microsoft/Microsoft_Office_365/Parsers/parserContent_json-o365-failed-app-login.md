#### Parser Content
```Java
{
Name = json-o365-failed-app-login
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|skyformation|""", """failed to login""", """"userPrincipalName":"""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """"userDisplayName":"({user_fullname}[^"]+)""",
    """"userPrincipalName":"({user_email}[^@]+@[^"]+)""",
    """"userId":"({user_sid}[^"]+)""",
    """"appDisplayName":"({app}[^"]+)""",
    """"ipAddress":"({src_ip}[^"]+)""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"failureReason":"({failure_reason}[^"]+)""",
    """"createdDateTime":"({time}[^"]+)""",
    """"countryOrRegion":"({country_code}[^"]+)""",
    """"additionalDetails":"({additional_info}[^"]+)""",
    """"operatingSystem":"({os}[^"]+)""",
    """"browser":"({browser}[^"]+)""",
    """login-({outcome}failed)"""
  ]
}
```