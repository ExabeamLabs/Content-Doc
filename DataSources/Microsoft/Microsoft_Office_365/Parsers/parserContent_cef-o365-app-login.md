#### Parser Content
```Java
{
Name = cef-o365-app-login
    Vendor = Microsoft
    Product = Microsoft Office 365
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|sk4-login-""","""request=""" ]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]{1,2000} Skyformation""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wsuser=(\w+-\w+-\w+-\w+-\w+|({user_email}[^@\s]{1,2000}?@[^@\s]{1,2000}?)|({user}[^@\s]{1,2000}?))\s{1,100}(\w+=|$)""",    
      """\Wsuser=[^@\s]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
      """\Wrequest=({outcome}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\WflexString1=({activity}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\WdestinationServiceName\s{0,100}=({app}({event_subtype}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
      """\WsourceServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\WoldFile=({user_agent}[^,]{1,2000}?)\s{1,100}(\w+=|$)""",
      """"failureReason":"({failure_reason}[^"]{1,2000})""",
      """"userDisplayName":"({user_fullname}({user_firstname}[^\s"]{1,2000}?)\s{1,100}({user_lastname}[^\s"\(\),]{1,2000}))\s{0,100}[^"]{0,2000}?"""",
      """"userDisplayName":"({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100}
```