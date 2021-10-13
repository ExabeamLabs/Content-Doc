#### Parser Content
```Java
{
Name = cef-o365-app-login-1
    Vendor = Microsoft
    Product = Office 365
    Lms = ArcSight
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """destinationServiceName=Office 365""", """"isInteractive":""", """"errorCode":""", """"clientAppUsed":""", """"failureReason":""", """dproc=Graph Sign-In"""  ]
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
      """"appDisplayName":"({app}[^"]{1,2000})"""",
      """\WsourceServiceName=({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
      """\WoldFile=({user_agent}[^,]{1,2000}?)\s{1,100}(\w+=|$)""",
      """"failureReason":"({failure_reason}[^"]{1,2000})""",
      """"userDisplayName":"({user_fullname}({user_firstname}[^\s"]{1,2000}?)\s{1,100}({user_lastname}[^\s"\(\),]{1,2000}))\s{0,100}[^"]{0,2000}?"""",
      """"userDisplayName":"({user_fullname}({user_lastname}[^",\s]{1,2000})\s{0,100},\s{0,100}({user_firstname}[^",]{1,2000}?))\s{0,20}(\(\w+\))?"""",
      """"userPrincipalName":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})""",
      """"userPrincipalName":"[^@\s]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s"]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))"""",
      """\sreason=({additional_info}[^=]{1,2000}?)\s{0,100}\w+=""",
      """city":"({location_city}[^",]{1,2000})""",
      """state":"({location_state}[^",]{1,2000})""",
      """countryOrRegion":"({country_code}[^",]{1,2000})""",
      """"browser":"({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|IE|Edge)""",
      """"operatingSystem":"({os}[^",]{1,2000})"""",
      """deviceDetail":\{[^\}]{1,2000}?displayName":"({src_host}[^",]{1,2000}?)\s{0,100}"""",
      """conditionalAccessStatus":"({status}[^",]{1,2000})"""",
      """"clientAppUsed":"({object}[^",]{1,2000})""",
      """"resourceDisplayName":"({resource}[^",]{1,2000})"""
      """"errorCode":({error_code}\d+)"""
      """"signinErrorCode":({error_code}\d+)"""
    ]
}
```