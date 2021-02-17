#### Parser Content
```Java
{
Name = s-amag-badge-access
    Vendor = AMAG
  Product = Symmetry Access Control
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """WhereName="""", """TxnConditionName="""", """DateTimeOfTxn=""""]
    Fields = [
      """exabeam_host=([^=]+?@\s*)?({host}[\w\.-]+)""",
      """[^\w]DateTimeOfTxn="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """[^\w]TxnConditionName="(\s+|({outcome}[^"]+))"""",
      """[^\w]WhereName="(\s+|({location_door}[^"]+))"""",
      """[^\w]FullName="(\s+|({user_fullname}[^"]+))"""",
      """[^\w]FirstName="(\s+|({first_name}[^"]+))"""",
      """[^\w]LastName="(\s+|({last_name}[^"]+))"""",
      """[^\w]CardID="(\s+|({badge_id}[^"]+))"""",
      """[^\w]CardNumber="(\s+|({employee_id}[^"]+))"""",
      """[^\w]EmployeeNumber="(\s+|({employee_id}[^"]+))"""",
    ]
  }
```