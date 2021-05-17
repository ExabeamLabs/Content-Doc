#### Parser Content
```Java
{
Name = sk4-workday-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """sk4-login-failure""","""cat=access""","""workday"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[
    """reason=({failure_reason}[^"]{1,2000})\srequest""",
  ]
}
sk4-workday-login-template = {
    Vendor = Workday
    Product =  Workday
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """destinationServiceName=({app}[^ ]{1,2000})""",
      """dproc=({host}[^\s]{1,2000})\s{1,100}\w+=""",
      """msg=({additional_info}[^=]{1,2000}?)\s\w+=.""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """suser=;?({user}[^\s;]{1,2000})""",
      """"{1,20}authenticationType"{1,20}:"{1,20}({auth_method}[^"]{1,2000})"{1,20}""",
      """"authenticationChannel"{1,20}:"{1,20}({auth_method}[^"]{1,2000})""",
      """"signonDateTime"{1,20}:({time}\d{1,100})""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    ]

```