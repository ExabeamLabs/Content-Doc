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
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w\.-]{1,2000})""",
      """[^\w]DateTimeOfTxn="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """[^\w]TxnConditionName="(\s{1,100}|({outcome}[^"]{1,2000}))"""",
      """[^\w]WhereName="(\s{1,100}|({location_door}[^"]{1,2000}))"""",
      """[^\w]FullName="(\s{1,100}|({user_fullname}[^"]{1,2000}))"""",
      """[^\w]FirstName="(\s{1,100}|({first_name}[^"]{1,2000}))"""",
      """[^\w]LastName="(\s{1,100}|({last_name}[^"]{1,2000}))"""",
      """[^\w]CardID="(\s{1,100}|({badge_id}[^"]{1,2000}))"""",
      """[^\w]CardNumber="(\s{1,100}|({employee_id}[^"]{1,2000}))"""",
      """[^\w]EmployeeNumber="(\s{1,100}|({employee_id}[^"]{1,2000}))"""",
    ]
  }
```