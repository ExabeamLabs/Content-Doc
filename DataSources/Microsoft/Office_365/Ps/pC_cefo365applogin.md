#### Parser Content
```Java
{
Name = cef-o365-app-login
    Vendor = Microsoft
    Product = Office 365
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """destinationServiceName =Office 365""", """"appDisplayName":""", """"mfaAuthMethod":""", """"signinDateTime":""", """"failureReason":""", """dproc=Deprecated - signins-events"""  ]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]{1,2000} """,
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wsuser=(\w{1,2000}-\w{1,2000}-\w{1,2000}-\w{1,2000}-\w{1,2000}|Sync|System|NotApplicable|({user_email}[^@\s]{1,2000}?@[^@\s]{1,2000}?)|({user}[^@\s]{1,2000}?))\s{1,100}(\w{1,100}=|$)""",    
      """\Wsuser=[^@\s]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
      """\Wrequest=({outcome}[^=]{1,2000}?)\s{1,100}(\w{1,100}=|$)""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\WflexString1=({activity}[^=]{1,2000}?)\s{1,100}(\w{1,100}=|$)""",
      """\WdestinationServiceName\s{0,100}=({app}({event_subtype}[^=]{1,2000}?))\s{1,100}(\w{1,100}=|$)""",
      """"appDisplayName":"({app}[^"]{1,2000})"""",
      """\WsourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w{1,100}=|$)""",
      """\WoldFile=({user_agent}[^,]{1,2000}?)\s{1,100}(\w{1,100}=|$)""",
      """"failureReason":"({failure_reason}[^"]{1,2000})""",
      """"userDisplayName":"({user_fullname}({user_firstname}[^\s"]{1,2000}?)\s{1,100}({user_lastname}[^\s"\(\),]{1,2000}))\s{0,100}[^"]{0,2000}?"""",
      """"userDisplayName":"({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100

}
```