#### Parser Content
```Java
{
Name = okta-app-activity
    Conditions = [ """core.user_auth.session_created_using_token""", """"published":""" ]
  
okta-app-activity = {
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = Direct
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\d{1,100}:\d{1,100} ({host}[^\s]{1,2000}) \{""",
    """"published":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"ipAddress":\s{0,100}"({src_ip}[^"]{1,2000})"""",
      """"action":\s{0,100}\{.*?"objectType":\s{0,100}"({activity}[^"]{1,2000})".+?\}""",
      """"action":\s{0,100}\{.*?"objectType":\s{0,100}"[^"]{0,2000}?({outcome}error)".+?\}""",
      """"categories":\s{0,100}\["({activity}[^"]{1,2000})"""",
      """"actors":\[.*?\{.*?"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"actors":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"displayName":\s{0,100}"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}))"""",
      """"displayName":"((?i)Unknown|RSA-OKTA Admin|AD-OKTA Admin|({user_fullname}[^"]{1,2000}?))\s{0,100}"[^\}\]]{0,2000}"objectType":"User"""",
      """"actors":\[.*?\{.*?"login":"({user}[^"\s@]{1,2000})"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"actors":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"login":\s{0,100}"({user}[^"\s@]{1,2000})"""",
      """"actors":\[.*?\{.*?"login":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"actors":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"login":\s{0,100}"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
      """"actors":\[.*?\{.*?"login":"[^@]{1,2000}@({email_domain}[^"]{1,2000})"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"actors":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"login":\s{0,100}"[^@]{1,2000}@({email_domain}[^"]{1,2000})"""",
      """"targets":\[.*?\{.*?"login":"({target_user}[^"]{1,2000})"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"targets":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"login":\s{0,100}"({target_user}[^"]{1,2000})"""",
      """"targets":\[.*?\{.*?"login":"({account_name}[^@\s"]{1,2000})@({target_domain}[^"]{1,2000})"[^\{\}]{1,2000}?"objectType":"User".*?\}""",
      """"targets":\s{0,100}\[\{[^\{\}]{0,2000}?"objectType":\s{0,100}"User"[^\]]{0,2000}?"login":\s{0,100}({account_name}[^@\s"]{1,2000})@({target_domain}[^"]{1,2000})"""",
      """"actors":\[.*?\{.*?"id":"({user_agent}[^"]{1,2000})"[^\{\}]{1,2000}?"objectType":"Client".*?\}""",
      """"actors":\s{0,100}\[\{[^\]]{0,2000}?"objectType":\s{0,100}"Client"[^\]]{0,2000}?"id":\s{0,100}"({user_agent}[^"]{1,2000})"""",
      """"message":\s{0,100}"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
      """({app}Okta)""",
      """requestClientApplication=({app}.+?)\s{0,100}\w+=""",
      """"targets":\[.*?\{.*?"displayName":"({app}[^"]{1,2000})"[^\{\}]{1,2000}?"objectType":"AppInstance".*?\}""",
      """"targets":\s{0,100}\[\{[^\]]{0,2000}?"objectType":\s{0,100}"AppInstance"[^\]]{0,2000}?"displayName":\s{0,100}"({app}[^"]{1,2000})"""",
      """"type":"AppInstance"[^\}\]]{0,2000}"displayName":"({app}[^"]{1,2000}?)\s{0,100}"""",
      """requestUri":\s{0,100}"({request_uri}[^"]{1,2000}?)\s{0,100}"""",
      """"id":"({object}[^"]{1,2000})"[^\}\]]{0,2000}"objectType":"AppInstance"""",
      """"objectType":"AppInstance"[^\}\]]{0,2000}"id":"({object}[^"]{1,2000})"""",
    ]
    DupFields = ["target_user->account_name", "target_domain->account_domain"
}
```