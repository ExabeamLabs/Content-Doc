#### Parser Content
```Java
{
Name = s-shibboleth-sso-1
  Vendor = Shibboleth SSO
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyyMMdd'T'HHmmss"
  Conditions = [ """<cont-3877_conditions>""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d{8}T\d{6}Z)\|""",
    """([^\|]*\|){3}({app}[^\|]+)\|""",
    """([^\|]*\|){8}({user}[^\|]+)\|""",
  ]
}
```