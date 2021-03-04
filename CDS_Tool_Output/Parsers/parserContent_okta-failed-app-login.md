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

}

OktaParsers = [

${OktaParserTemplates.s-okta-app-login}{
  Name = cef-okta-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"displayMessage":"User single sign on to app"""", """"result":"SUCCESS"""" ]
}
```