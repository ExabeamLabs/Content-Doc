#### Parser Content
```Java
{
Name = cef-o365-app-login
    Vendor = Microsoft
    Product = Office 365
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Office 365""", """|sk4-login-""","""request=""" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+\w) ({host}[\w\-.]+) Skyformation""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
      """\Wsuser=(({user_email}[^@\s]+?@[^@\s]+?)|({user}[^@\s]+?))\s+(\w+=|$)""",    
      """\Wsuser=[^@\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s+""",
      """\Wrequest=({outcome}[^=]+?)\s+(\w+=|$)""",
      """([^\|]*\|){5}({activity}[^\|]+)""",
      """\WflexString1=({activity}[^=]+?)\s+(\w+=|$)""",
      """\WdestinationServiceName\s*=({app}({event_subtype}.+?))\s+(\w+=|$)""",
      """\WsourceServiceName=({app}.+?)\s+(\w+=|$)""",
      """\WoldFile=({user_agent}.+?)\s+(\w+=|$)""",
      """"failureReason":"({failure_reason}[^"]+)""",
      """"userDisplayName":"({user_fullname}[^"\s,]+\s+[^",]+)"""",
      """"userDisplayName":"({user_lastname}[^",]+),\s*({user_firstname}[^",]+?)"""",
      """"userPrincipalName":"({user_email}[^"\s@]+@[^"\s@]+)""",
      """"userPrincipalName":"[^@\s]*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))"""",
    ]
}
```