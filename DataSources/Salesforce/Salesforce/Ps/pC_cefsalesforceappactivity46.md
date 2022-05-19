#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-46
  Product = Salesforce
  Conditions = [ """flexString1=frozeuser""", """destinationServiceName =Sales Cloud""" ]

cef-salesforce-app-activity = {
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s{1,100}""",
    """\Wsuser=({user_email}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=({activity}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString2=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """({app}Sales Cloud)""",
    """\Wduser=({object}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  
}
```