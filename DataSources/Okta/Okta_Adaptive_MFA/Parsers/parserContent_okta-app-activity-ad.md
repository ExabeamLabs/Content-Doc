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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """lastUpdated":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""", 
    """samAccountName":\s{0,100}"({user}[^"]+)""",
    """description":\s{0,100}"({activity}[^"]+)""",
    """label":\s{0,100}"({domain}[^"]+)""",
    """name".*?,\s{0,100}"id":\s{0,100}"({object}[^"]+)""", 
    """type":\s{0,100}"({object_type}[^"]+)""",
    """members":\s{0,100}\[({members}[^\]]+?)\s{0,100}(\]|$)"""
    """assignedApps":\s{0,100}\[(:-?|({assigned_apps}[^\]]+))"""
    """"app":\s\{.*?"name":\s{0,100}"({app}[^"]+)"""

  ]
}
```