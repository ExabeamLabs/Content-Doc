#### Parser Content
```Java
{
Name = azure-ad-member-removed-1
  Vendor = Microsoft
  Product = Azure
  Lms = Splunk
  DataType = "member-removed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"ActivityDisplayName":"Remove member from group"""", """"OperationName":"Remove""", """"ActivityDateTime":"""", """"ResourceId":"""" ]
  Fields = [
    """Group\.DisplayName\\",\\"oldValue\\":\\"\\{1,20}"({group_name}[^"\\]{1,2000})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"ActivityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
    """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"userPrincipalName\\":\\"({user_email}[^@"]{1,2000}@([^\."]{1,2000}\.[^"]{1,2000}?)?)\\?"""",
    """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"ipAddress\\":\\"({src_ip}[A-Fa-f:\d.]{1,2000}?)\\?"""",
    """"TenantId":"({account_id}[^"]{1,2000})""",
  ]


}
```