#### Parser Content
```Java
{
Name = accelion-kite-app-admin-login
  Product = Kiteworks
  DataType = "app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """admin_logged_in""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]

accelion-kite-app = {
  Vendor = Accellion
  Product = Kiteworks
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}\/*:*({additional_info}[^,]{1,2000})"""",
    """"{1,20}user_name"{1,20}:\s{0,100}"{1,20}(System|({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000})))"{1,20}"""
    """"{1,20}user_ip"{1,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})"{1,20}""",
    """"{1,20}application"{1,20}:\s{0,100}"{1,20}({app}[^"]{1,2000})"{1,20}""",
    """"{1,20}app_host"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"{1,20}""",
    """"{1,20}event"{1,20}:\s{0,100}"{1,20}({accesses}[^"]{1,2000})"{1,20}""",
    """"{1,20}user_agent"{1,20}:\s{1,100}"{1,20}({user_agent}[^"]{1,2000})?"{1,20}\,""",
    """"{1,20}url_host"{1,20}:\s{0,100}"{1,20}({url_host}[^"]{1,2000})?"{1,20}\,""",
    """"{1,20}size"{1,20}:\s{0,100}({bytes}\d{1,100})""",
    """"{1,20}mime":\s{0,100}"({mime}[^"]{1,2000})""",
  
}
```