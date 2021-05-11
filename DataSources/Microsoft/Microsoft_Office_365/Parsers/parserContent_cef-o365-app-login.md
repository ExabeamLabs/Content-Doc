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
      """exabeam_host=({host}[^\s]+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]+ Skyformation""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wsuser=(\w+-\w+-\w+-\w+-\w+|({user_email}[^@\s]+?@[^@\s]+?)|({user}[^@\s]+?))\s{1,100}(\w+=|$)""",    
      """\Wsuser=[^@\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
      """\Wrequest=({outcome}[^=]+?)\s{1,100}(\w+=|$)""",
      """([^\|]*\|){5}({activity}[^\|]+)""",
      """\WflexString1=({activity}[^=]+?)\s{1,100}(\w+=|$)""",
      """\WdestinationServiceName\s{0,100}=({app}({event_subtype}[^=]+?))\s{1,100}(\w+=|$)""",
      """\WsourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
      """\WoldFile=({user_agent}[^,]+?)\s{1,100}(\w+=|$)""",
      """"failureReason":"({failure_reason}[^"]+)""",
      """"userDisplayName":"({user_fullname}({user_firstname}[^\s"]+?)\s{1,100}({user_lastname}[^\s"\(\),]+))\s{0,100}[^"]*?"""",
      """"userDisplayName":"({user_fullname}({user_lastname}[^",\s]+)\s{0,100}
```