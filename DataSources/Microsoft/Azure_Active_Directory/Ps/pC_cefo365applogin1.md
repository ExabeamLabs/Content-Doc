#### Parser Content
```Java
{
Name = cef-o365-app-login-1
    Vendor = Microsoft
    Product = Azure Active Directory
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """destinationServiceName =Office 365""", """"isInteractive":""", """"errorCode":""", """"clientAppUsed":""", """"failureReason":""", """dproc=Graph Sign-In"""  ]
    Fields = [
      """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]{1,2000} """,
      """"ipAddress":"({src_ip}[A-Fa-f.:\d]{1,2000})""",
      """\WdestinationServiceName\s{0,100}=({app}({event_subtype}[^=]{1,2000}?))\s{1,100}(\w{1,100}=|$)""",
      """"appDisplayName":"(NotApplicable|({app}[^"]{1,2000}))"""",
      """\WoldFile=({user_agent}[^,]{1,2000}?)\s{1,100}(\w{1,100}=|$)""",
      """"failureReason":"({failure_reason}[^"]{1,2000})""",
      """"userDisplayName":"({user_fullname}({user_firstname}[^\s"]{1,2000}?)\s{1,100}({user_lastname}[^"\(\),]{1,2000}))\s{0,100}[^"]{0,2000}?"""",
      """"userDisplayName":"({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100

}
```