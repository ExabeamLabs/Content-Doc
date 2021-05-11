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
    """({host}[^\s]+)\s\S+\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s{1,100}({dest_ip}[A-Fa-f:\d.]+)""",
    """DESCRIPTION="({additional_info}[^".]+)""",
    """SOURCE-IP-ADDRESS="({src_ip}[A-Fa-f:\d.]+)""",
    """USER_NAME="({user}[^"]+)""",
    """POLICY_ID="({policy}[^"]+)""",
    """STATUS="({outcome}[^"]+)"""
    ]
  DupFields = ["additional_info->failure_reason"]
}
```