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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """lastUpdated":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""", 
    """samAccountName":\s*"({user}[^"]+)""",
    """description":\s*"({activity}[^"]+)""",
    """label":\s*"({domain}[^"]+)""",
    """name".*?,\s*"id":\s*"({object}[^"]+)""", 
    """type":\s*"({object_type}[^"]+)""",
    """members":\s*\[({members}[^\]]+?)\s*(\]|$)"""
    """assignedApps":\s*\[(:-?|({assigned_apps}[^\]]+))"""
    """"app":\s\{.*?"name":\s*"({app}[^"]+)"""

  ]
}
```