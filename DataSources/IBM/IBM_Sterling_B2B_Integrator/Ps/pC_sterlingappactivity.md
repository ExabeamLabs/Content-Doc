#### Parser Content
```Java
{
Name = sterling-app-activity
  DataType = "app-activity"
  Conditions = [ """,Edit: Add Permission,""", """sterling"""]

sterling-integrator {
    Vendor = IBM
    Product = IBM Sterling B2B Integrator
    Lms = Syslog
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [
      """\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\+\d\d:\d\d)\s{1,100}sterling""",
      """sterling(\s-){3}\s{1,100}({host}[^,]{1,2000})""",
      """sterling(?:\s-){3}\s{1,100}(?:[^,]{1,2000},)({subcategory}[^,]{1,2000})""",
      """sterling(?:\s-){3}\s{1,100}(?:[^,]{1,2000},){2}({object}[^,]{1,2000})""",
      """sterling(?:\s-){3}\s{1,100}(?:[^,]{1,2000},){3}({action}[^,]{1,2000})""",
      """sterling(?:\s-){3}\s{1,100}(?:[^,]{1,2000},){4}({description}[^,]{1,2000})""",
      """sterling(?:\s-){3}\s{1,100}(?:[^,]{1,2000},){5}({user_id}[^,]{1,2000})""",
    
}
```