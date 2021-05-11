#### Parser Content
```Java
{
Name = q-okta-app-activity
  DataType = "app-activity"
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType"""", """"client"""", """"target"""", """"securityContext"""", """"actor"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"published"{1,20}:"{1,20}({time}[^",]+)"{1,20}""",
    """({app}(?i)Okta)""",
    """"{1,20}actor"{1,20}:\{[^\{\}]*?"{1,20}alternateId"{1,20}:"{1,20}(system@okta\.com|({user_email}[^@]+@({domain}[^\.]+\.[^",]+))|(unknown|({user}[^",]+)))"{1,20}
```