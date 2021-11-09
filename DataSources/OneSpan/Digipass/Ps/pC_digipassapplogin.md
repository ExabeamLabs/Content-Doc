#### Parser Content
```Java
{
Name = digipass-app-login
  DataType = "app-login"
  Conditions = [ """, Authentication, """, """"User authentication was successful."""", """ Input Details ["""", """ Output Details ["""", """ Back-End Authentication ["""  ]   
}
digipass-events  = {
    Vendor = OneSpan
    Product = Digipass
    Lms = Splunk
    TimeFormat = "yyyy/MM/dd HH:mm:ss.SSS"
    Fields = [
      """({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d\.\d\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\d\d\d,\s({outcome}[^,]{1,2000}),""",
      """Domain\s\["({domain}[^"]{1,2000})"""",
      """User ID\s{1,100}\["({user}[^"]{1,2000})"""",
      """Authentication,([^,]{0,2000},)\s({event_code}[^,]{1,2000}),""",
      """Authentication,([^,]{0,2000},){2}\s{0,100}"({event_name}[^"]{1,2000})""",
      """Source Location\s{1,100}\["({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """Application\s{1,100}\["({app}[^"]{1,2000})"""",
      """Error Message:\s{1,100}'({failure_reason}[^']{1,2000})""",
      """Policy ID\s{1,100}\["({auth_method}[^"]{1,2000})"""",
      """Protocol ID\s:\s{0,100}({protocol}[^},]{1,2000})"""
    ]}
```