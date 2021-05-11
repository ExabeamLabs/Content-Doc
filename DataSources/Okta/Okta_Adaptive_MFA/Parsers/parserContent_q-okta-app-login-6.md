#### Parser Content
```Java
{
Name = q-okta-app-login-6
  DataType = "app-login"
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType"""", """"policy.evaluate_sign_on"""", """policyType""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"published"{1,20}:"{1,20}({time}[^",]+)"{1,20}""",
    """"{1,20}actor"{1,20}:\{[^\{\}]*?"{1,20}alternateId"{1,20}:"{1,20}(system@okta\.com|({user_email}[^@]+@({domain}[^\.]+\.[^",]+))|(unknown|({user}[^",]+)))"{1,20}
```