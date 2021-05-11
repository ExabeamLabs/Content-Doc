#### Parser Content
```Java
{
Name = sk4-workday-app-login
  DataType = "app-login"
  Conditions = [ """sk4-login-success""","""cat=access""","""workday"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[]
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
      """dproc=({host}[^\s]+)\s{1,100}\w+=""",
      """msg=({additional_info}[^=]+?)\s\w+=.""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """suser=;?({user}[^\s;]+)""",
      """"{1,20}authenticationType"{1,20}:"{1,20}({auth_method}[^"]+)"{1,20}""",
      """"authenticationChannel"{1,20}:"{1,20}({auth_method}[^"]+)""",
      """"signonDateTime"{1,20}:({time}\d{1,100})""",
      """([^\|]*\|){5}({activity}[^\|]+)""",
      """\Wdproc=(|({dproc}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    ]

```