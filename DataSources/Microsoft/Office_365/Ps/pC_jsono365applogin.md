#### Parser Content
```Java
{
Name = json-o365-app-login
  Vendor = Microsoft
  Product = Office 365
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"appDisplayName":""", """successfully logged in""", """"userPrincipalName":"""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """"userDisplayName":"({user_fullname}[^"]{1,2000})""",
    """"userPrincipalName":"({user_email}[^@]{1,2000}@[^"]{1,2000})""",
    """"userId":"({user_sid}[^"]{1,2000})""",
    """"appDisplayName":"({app}[^"]{1,2000})""",
    """"ipAddress":"({src_ip}[^"]{1,2000})""",
    """"city":"({location_city}[^"]{1,2000})""",
    """"state":"({location_state}[^"]{1,2000})""",
    """"createdDateTime":"({time}[^"]{1,2000})""",
    """"countryOrRegion":"({country_code}[^"]{1,2000})""",
    """"additionalDetails":"({additional_info}[^"]{1,2000})""",
    """"operatingSystem":"({os}[^"]{1,2000})""",
    """"browser":"({browser}[^"]{1,2000})""",
    """login-({outcome}success)""",
  ]


}
```