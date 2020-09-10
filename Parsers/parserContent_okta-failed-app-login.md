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

}

OktaParsers = [

${OktaParserTemplates.s-okta-app-login}{
  Name = cef-okta-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"displayMessage":"User single sign on to app"""", """"result":"SUCCESS"""" ]
}
```