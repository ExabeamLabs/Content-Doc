#### Parser Content
```Java
{
Name = sk4-workday-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """sk4-login-failure""","""cat=access""","""workday"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[
    """reason=({failure_reason}[^"]+)\srequest""",
  ]
}
sk4-workday-login-template = {
    Vendor = Workday
    Product =  Workday
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """destinationServiceName=({app}[^ ]+)""",
      """dproc=({host}[^ ]+)""",
      """msg=({additional_info}.+?)\s\w+=.""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """suser=;?({user}[^\s;]+)""",
      """"+authenticationType"+:"+({auth_method}[^"]+)"+""",
      """"authenticationChannel"+:"+({auth_method}[^"]+)""",
      """"signonDateTime"+:({time}\d+)""",
    ]

```