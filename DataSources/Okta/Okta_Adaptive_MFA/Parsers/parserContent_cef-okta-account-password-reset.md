#### Parser Content
```Java
{
Name = cef-okta-account-password-reset
  DataType = "account-password-reset"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """destinationServiceName=Okta""", """"eventType":"system.email.password_reset.sent_message""""]
  Fields = ${OktaParserTemplates.json-okta-auth.Fields}[
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+({target_user}[^"@]+@({target_domain}[^"]+)))""",
    """target(s)?"+:[^\]]+?"+type"+:"+User"+[^\]\}]+?"+(alternateId|emailAddress)"+:(null|"+(({target_domain}[^\\\/]+)[\/\\]+)?({target_user}[^"]+))"""
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
    """"outcome":[^\]]*?"result"\s*:\s*"({outcome}[^"]+)"""",
    """outcome":[^\]]*?"result":"?(null|({outcome_result_at}[^\"]+))"?,"reason":"?(null|({outcome_reason_at}[^"]+))""",
  ]

```