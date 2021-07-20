#### Parser Content
```Java
{
Name = okta-app-activity-ad
  Vendor = Okta
  Product = Okta Adaptive MFA
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """samAccountName":""", """windowsDomainQualifiedName"""]
  Fields=[
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """lastUpdated":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""", 
    """samAccountName":\s{0,100}"({user}[^"]{1,2000})""",
    """description":\s{0,100}"({activity}[^"]{1,2000})""",
    """label":\s{0,100}"({domain}[^"]{1,2000})""",
    """name".*?,\s{0,100}"id":\s{0,100}"({object}[^"]{1,2000})""", 
    """type":\s{0,100}"({object_type}[^"]{1,2000})""",
    """members":\s{0,100}\[({members}[^\]]{1,2000}?)\s{0,100}(\]|$)"""
    """assignedApps":\s{0,100}\[(:-?|({assigned_apps}[^\]]{1,2000}))"""
    """"app":\s\{.*?"name":\s{0,100}"({app}[^"]{1,2000})"""

  ]
}
```