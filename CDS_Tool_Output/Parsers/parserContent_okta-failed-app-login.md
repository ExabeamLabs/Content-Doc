#### Parser Content
```Java
{
okta-failed-app-login = {
    Vendor = Okta
    Product = Okta MFA
    Lms = Splunk
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """"IPAddress":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """"user":"({user_email}[^@"\s]+?@[^@"\s]+)""",
      """"EventDetails":(\[|")({failure_reason}.*?)(\]|"),"\w+":"""
      """Sign-in Failed\s+-\s+({failure_reason}[^":,]+)""",
      """"Source":"({additional_info}[^"]+?)"""",
      """"Source":\[({additional_info}[^\]]+)""",
      """"Host":"({host}[^"]+?)"""",
      """"Host":\["({host}[^",]+)""",
      """({app}(o|O)kta)""",
      """"DisplayName":"({user_fullname}[^"]+?\s[^"]+)""""
      """"DisplayName":\["({user_fullname}[^,"]+?\s[^,"]+)"""
    ]
}


s-okta-app-activity-2 {
   Vendor = Okta
   Product = Okta MFA
   Lms = Splunk
   DataType = "app-activity"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
   Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """({alert_severity}[^"]+)","({activity}[^"]+)","({event_name}[^"]+)","(?:|[^"]+)","(?:|[^"]+)","({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
      """"(JOB|WEB)","(?:|[^"]+)","(?:|({activity}[^"]+))","(|[^"]+)","User","(|({user_email}[^"]+))","(|({user_fullname}[^"]+))",""",
      """"(JOB|WEB)","(?:|[^"]+)","(?:|({activity}[^"]+))"""",
      """"AppUser","(|({user_email}[^@"]+@[^"]+)|({user}[^"]+))","(|(({user_lastname}[^,]+),\s*({user_firstname}[^"]+)))",""",
      """"\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ","(|({outcome}[^"]+))","(|[^"]+)","(|({user_id}[^"]+))","User","({user_fullname}[^"]+)","({user_email}[^"]+)","(|[^"]+)","(|[^"]+)","(|[^"]+)","(|({auth_method}[^"]+))","(|[^"]+)","(|[^"]+)","(|[^"]+)","(|[^"]+)","(|[^"]+)","(|({user_agent}[^"]+))","(|({os}[^"]+))","(|({browser}[^"]+))","(|({location_country}[^"]+))","(|({location_city}[^"]+))",""",
   ]
}

json-okta-auth = {
  Vendor = Okta
  Product = Okta
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields=[
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"published"+\s*:\s*"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """({app}OKTA|Okta)""",
    """"city":"({location_city}[^",]+)""",
    """"state":"({location_state}[^",]+)""",
    """"country":"({location_country}[^",]+)""",
    """"ipAddress"+\s*:\s*"+({src_ip}[^",]+)""",
    """"rawUserAgent"+\s*:\s*"+(Unknown|unknown|UNKNOWN|({user_agent}[^",]+))""",
    """"browser"+\s*:\s*"+(Unknown|unknown|UNKNOWN|({browser}[^",]+))""",
    """"os"+\s*:\s*"+(Unknown|unknown|UNKNOWN|({os}[^",]+))""",
    """"action"+:.+?"+message"+:"+({event_name}[^",]+)"""
    """"displayMessage"\s*:\s*"({event_name}[^",]+)""",
    """"action"+:.+?"+objectType"+:"+({activity}[^",]+)""",
    """"legacyEventType"+:"+({activity}[^",]+)""",
    """"reason":"({failure_reason}[^"]+)"""
    """"target":.+?"displayName"\s*:\s*"({object}[^"]+[^\s])"""",
    """request"+:.+?User.+?"+displayName"+:(null|"+(Okta System|Unknown|unknown|UNKNOWN|(?:({user_firstname}[^,"]+),\s*({user_lastname}[^"]+)|({user_fullname}[^"]+)))")""",
    """"actor"+.+?"+type"+:"+User.+?displayName"+:(null|"+(Okta System|Okta Admin|Unknown|unknown|UNKNOWN|(?:({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)|({user_fullname}[^"]+))))""",
    """request"+:.+?"+type"+:"+User"+,"+alternateId"+:(null|"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+))))""",
    """"actor"+:[^\]]*?"+type"+:"+User"+,"+alternateId"+\s*:\s*"+(system@okta\.com|(?:({user_email}[^"@]+@({domain}[^"]+))|({user}[^"]+)))"""",
    """"login":\s*"({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"login":\s*"[^@]+@({domain}[^"]+)""""
    """requestUri":\s*"({request_uri}[^"]+?)\s*"""",
    """"outcome":\s*\{[^\{\}]*?"result":\s*"({outcome}[^"]+)""",
  ]
  DupFields = ["domain->email_domain"]
}
```