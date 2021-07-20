#### Parser Content
```Java
{
Name = rsa-securid-auth-fail
  Vendor = RSA
  Product = SecurID
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ SINGLEPOINT """, """ RADIUS_USER_TOKENCODE_AUTHENTICATION """, """RADIUS_RESPONSE_TYPE="Access-Challenge"""", """STATUS="FAIL"""" ]
  Fields = [
    """({host}[^\s]{1,2000})\s\S+\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s{1,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """DESCRIPTION="({additional_info}[^".]{1,2000})""",
    """SOURCE-IP-ADDRESS="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """USER_NAME="({user}[^"]{1,2000})""",
    """POLICY_ID="({policy}[^"]{1,2000})""",
    """STATUS="({outcome}[^"]{1,2000})"""
    ]
  DupFields = ["additional_info->failure_reason"]
}
```