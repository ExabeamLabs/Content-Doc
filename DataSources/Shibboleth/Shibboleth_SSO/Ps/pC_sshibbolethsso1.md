#### Parser Content
```Java
{
Name = s-shibboleth-sso-1
  Vendor = Shibboleth
  Product = Shibboleth SSO
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyyMMdd'T'HHmmss"
  Conditions = [ """<cont-3877_conditions>""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{8}T\d{6}Z)\|""",
    """([^\|]{0,2000}\|){3}({app}[^\|]{1,2000})\|""",
    """([^\|]{0,2000}\|){8}({user}[^\|]{1,2000})\|""",
  ]
}
```