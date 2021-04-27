#### Parser Content
```Java
{
Name = json-okta-app-login
  DataType = "app-login"
  Conditions = [ """"app.ad.login.success"""", """requestClientApplication=Okta""", """|Skyformation|""" ]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """({outcome}(?i)success)"""
  ]
}
json-okta-auth = {
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"+\s*:\s*"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({app}(?i)Okta)""",
    """requestClientApplication=({app}[^=]+?)\s*\w+=""",
    """"city":"({location_city}[^",]+)""",
    """"state":"({location_state}[^",]+)""",
    """"country":"({location_country}[^",]+)""",
    """"ipAddress"+\s*:\s*"+({src_ip}[^",]+)""",
    """"rawUserAgent"+\s*:\s*"+((?i)unknown|({user_agent}[^",]+))""",
    """"browser"+\s*:\s*"+((?i)unknown|({browser}[^",]+))""",
    """"os"+\s*:\s*"+((?i)unknown|({os}[^",]+))""",
    """"action"+:.+?"+message"+:"+({event_name}[^",]+)"""
    """"displayMessage"\s*:\s*"({event_name}[^",]+)""",
    """"action"+:.+?"+objectType"+:"+({activity}[^",]+)""",
    """"legacyEventType"+:"+({activity}[^",]+)""",
    """"reason":"({failure_reason}[^"]+)"""
    """"target(s)?"+:[^\}\]]+?"+displayName"+\s*:\s*"+((?i)unknown|({object}[^"]+[^\s]))"""",
    """request"+:.+?User.+?"+displayName"+:(null|"+(Okta System|(?i)unknown|(?:({user_firstname}[^,"]+),\s*({user_lastname}[^"]+)|({user_fullname}[^"]+)))")""",
    """"actor"+.+?"+type"+:"+User.+?displayName"+:(null|"+(Okta System|Okta Admin|(?i)unknown|(?:({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)|({user_fullname}[^"]+))))""",
    """request"+:.+?"+type"+:"+User"+,"+alternateId"+:(null|"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|(({=domain}[^\\\/]+)[\/\\]+)?({user}[^"]+))))""",
    """"actor"+:[^\]]*?"+type"+:"+User"+,"+alternateId"+\s*:\s*"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+)))"""",
    """"login":\s*"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"login":\s*"[^@]+@({domain}[^"]+)""""
    """requestUri":\s*"({request_uri}[^"]+?)\s*"""",
    """"outcome":\s*\{[^\{\}]*?"result":\s*"({outcome}[^"]+)"""
  ]

```