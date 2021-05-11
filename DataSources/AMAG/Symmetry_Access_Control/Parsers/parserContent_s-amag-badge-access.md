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
      """exabeam_host=([^=]+?@\s{0,100})?({host}[\w\.-]+)""",
      """[^\w]DateTimeOfTxn="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """[^\w]TxnConditionName="(\s{1,100}|({outcome}[^"]+))"""",
      """[^\w]WhereName="(\s{1,100}|({location_door}[^"]+))"""",
      """[^\w]FullName="(\s{1,100}|({user_fullname}[^"]+))"""",
      """[^\w]FirstName="(\s{1,100}|({first_name}[^"]+))"""",
      """[^\w]LastName="(\s{1,100}|({last_name}[^"]+))"""",
      """[^\w]CardID="(\s{1,100}|({badge_id}[^"]+))"""",
      """[^\w]CardNumber="(\s{1,100}|({employee_id}[^"]+))"""",
      """[^\w]EmployeeNumber="(\s{1,100}|({employee_id}[^"]+))"""",
    ]
  }
```