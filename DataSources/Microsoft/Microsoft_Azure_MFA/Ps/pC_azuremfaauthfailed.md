#### Parser Content
```Java
{
Name = azure-mfa-auth-failed
  DataType = authentication-failed
  Conditions = [ """|pfsvc|""", """Pfauth failed for user""", """Call status:""" ]

azure-mfa-auth = {
    Vendor = Microsoft
    Product = Microsoft Azure MFA
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z\|""",
      """Pfauth (?:failed|succeeded) for user '(?:({user_email}[^@']{1,2000}@[^']{1,2000})|({user}[^']{1,2000}))'""",
      """Call status:\s{0,100}({call_status}.+?)\s{0,100}-\s{0,100}"""",
      """Pfauth failed for user.*?\-\s{0,100}"({failure_reason}[^"]{1,2000})"""",
      """({auth_method}Pfauth)""",
      """\sfrom\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:({src_port}\d{1,100}))?"""
    
}
```