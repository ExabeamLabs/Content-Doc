#### Parser Content
```Java
{
Name = json-o365-app-login
  Vendor = Microsoft
  Product =  Office 365
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """CEF:""", """|skyformation|""", """successfully logged in""", """"userPrincipalName":"""" ]
  Fields = [
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """"userDisplayName":"({user_fullname}[^"]+)""",
    """"userPrincipalName":"({user_email}[^@]+@[^"]+)""",
    """"userId":"({user_sid}[^"]+)""",
    """"appDisplayName":"({app}[^"]+)""",
    """"ipAddress":"({src_ip}[^"]+)""",
    """"city":"({location_city}[^"]+)""",
    """"state":"({location_state}[^"]+)""",
    """"createdDateTime":"({time}[^"]+)""",
    """"countryOrRegion":"({country_code}[^"]+)""",
    """"additionalDetails":"({additional_info}[^"]+)""",
    """"operatingSystem":"({os}[^"]+)""",
    """"browser":"({browser}[^"]+)""",
    """login-({outcome}success)""",
  ]
}
```