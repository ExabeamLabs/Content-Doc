#### Parser Content
```Java
{
Name = microsoft-app-activity-8
  Conditions= [ """"src-application-name":"Office 365"""", """"event-name":"authz-group-created"""", """initiatedBy":""", """"src-endpoint":"Graph Directory Audit logs"""", """"category":"GroupManagement"""" ]
}
microsoft-app-activity-3 = {
    Vendor = Microsoft
    Product = Office 365
    Lms = Direct
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{0,3})?Z)"""",
      """"event-name":"({activity}[^"]{1,2000})"""",
      """"result":"({outcome}[^"]{1,2000})"""",
      """"activityDisplayName":"({activity}[^"]{1,2000})"""",
      """user-email":"({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
      """initiatedBy":\{[^\}]{1,2000}?userPrincipalName":"(({user_email}[^@"]{1,2000}@[^"]{1,2000})|({user}[^"]{1,2000}))"""",
      """"src-application-name":"({app}[^"]{1,2000})"""",
      """key":"User-Agent","value":"({user_agent}[^"]{1,2000})"""",
      """ipAddress":"({src_ip}[a-fA-F\d.:]{1,2000})""""
    ]}
```